rule Windows_VulnDriver_NSecKrnl_6a5d3ceb {
    meta:
        author = "Elastic Security"
        id = "6a5d3ceb-d83d-45b3-a2d9-6590884335b6"
        fingerprint = "99dbd9def298ce7f312b9ac825ffb40b386743fd333d54b61f571a732ff645ae"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: NSecKrnl, Version: <= 3.6.12.2001"
        threat_name = "Windows.VulnDriver.NSecKrnl"
        reference_sample = "8f0aed4470879c2556689da8fdca417ca03d75cc6ef53feb2331eddb84e07e58"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 53 00 65 00 63 00 4B 00 72 00 6E 00 6C 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xd0][\x07-\x07])[\x0c-\x0c][\x00-\x00]|[\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00][\xd1-\xd1][\x07-\x07][\x0c-\x0c][\x00-\x00])/
        $str1 = "NSecKrnl64.pdb"
        $str2 = "NSecKrnl" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}