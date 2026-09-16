rule Windows_VulnDriver_Nvidia_f058fb9a {
    meta:
        author = "Elastic Security"
        id = "f058fb9a-9537-4a3d-8c3e-7f8fc555f9bd"
        fingerprint = "72be939136c685bbacdb3584e2194bfb48aa56a9d775a2c718c1c4cb5de5ec39"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: nvoclock.sys, Version: <= 6.3.6.0"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "909f6c4b8f779df01ef91e549679aa4600223ac75bc7f3a3a79a37cee2326e77"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x03-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "nvoclock.pdb"
        $str2 = "NVIDIA System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}