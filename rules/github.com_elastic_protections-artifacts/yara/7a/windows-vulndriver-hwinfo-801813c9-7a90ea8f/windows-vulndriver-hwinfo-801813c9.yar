rule Windows_VulnDriver_HWiNFO_801813c9 {
    meta:
        author = "Elastic Security"
        id = "801813c9-1f44-40bd-ba76-6864b3b859fc"
        fingerprint = "01725d36e58fc125782bd221bacda8cf659d96b5fcee8a70f8bc520807e34e0e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: REALiX, Version: <= 8.60.0.0"
        threat_name = "Windows.VulnDriver.HWiNFO"
        reference_sample = "ff1ccef7374a1a5054a6f4437e3e0504b14ed76e17090cc6b1a4ec0e2da427a5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 45 41 4C 69 58 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 69 00 4E 00 46 00 4F 00 33 00 32 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x3b][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x3c-\x3c][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HWiNFO32.pdb"
        $str2 = "HWiNFO32/64 Kernel Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}