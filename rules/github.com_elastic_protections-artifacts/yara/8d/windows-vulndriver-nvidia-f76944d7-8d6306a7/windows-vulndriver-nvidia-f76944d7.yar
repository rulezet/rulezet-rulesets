rule Windows_VulnDriver_Nvidia_f76944d7 {
    meta:
        author = "Elastic Security"
        id = "f76944d7-9eff-40d1-bc54-d6cb35d14225"
        fingerprint = "f59234d5b150b1fcf31ed3ec16643a46e848b56248d1cc80f14466df3bc5b2f5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: NVoclock.RC, Version: <= 5.0.1636.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "d7c90cf3fdbbd2f40fe6a39ad0bb2a9a97a0416354ea84db3aeff6d925d14df8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 56 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 52 00 43 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x63][\x06-\x06])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x64-\x64][\x06-\x06]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x64-\x64][\x06-\x06])/
        $str1 = "nvoclock.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}