rule Windows_VulnDriver_Nvidia_7f6bfd41 {
    meta:
        author = "Elastic Security"
        id = "7f6bfd41-797a-42a2-a36b-42961c669fc4"
        fingerprint = "7c0808d272186bf4d7793931a33af4441089f35ed0c3c300f9d9245b008ec48d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 6.2.15.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "d54ac69c438ba77cde88c6efd6a423491996d4e8a235666644b1db954eb1da9c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00])/
        $str1 = "nvoclk64.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}