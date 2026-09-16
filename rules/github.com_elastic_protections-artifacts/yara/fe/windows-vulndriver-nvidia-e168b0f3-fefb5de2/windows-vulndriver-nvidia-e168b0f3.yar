rule Windows_VulnDriver_Nvidia_e168b0f3 {
    meta:
        author = "Elastic Security"
        id = "e168b0f3-0c2a-4036-86e5-b9d9507e0126"
        fingerprint = "9f335d8a64c47b82b8f5576ec2f47fa286a81267341a4d2d905dcde388566b6f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: nvoclock.sys, Version: <= 7.0.0.32"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "979017192bb021026dc9640a9ab43b24df445a07acbf6c5a4222e4486eb25d3d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x1f][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x20-\x20][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "nvr0int64.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}