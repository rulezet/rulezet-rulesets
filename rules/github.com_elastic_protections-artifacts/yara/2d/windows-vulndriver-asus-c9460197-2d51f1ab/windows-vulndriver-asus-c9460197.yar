rule Windows_VulnDriver_Asus_c9460197 {
    meta:
        author = "Elastic Security"
        id = "c9460197-8e24-4c8d-9832-3c6c6346a0c9"
        fingerprint = "7f4cbf351b9f2263d7736e46866a63f20aca8dc941e70de898481fda0be2f0f2"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Name: EIO.sys, Version: <= 1.9.7.0"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "cf69704755ec2643dfd245ae1d4e15d77f306aeb1a576ffa159453de1a7345cb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "EIO.pdb"
        $str2 = "ASUS VGA Kernel Mode Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}