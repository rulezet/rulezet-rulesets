rule Windows_VulnDriver_DTResearch_ec8d708a {
    meta:
        author = "Elastic Security"
        id = "ec8d708a-4cf6-44df-81af-b79d9a6cdb40"
        fingerprint = "4035c7a4c7e62f33db505caf49de39ee50de9fe8192ed2dea7597c48193155a1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: DT RESEARCH, INC. TAIWAN BRANCH, Version: <= 2.3.0.0"
        threat_name = "Windows.VulnDriver.DTResearch"
        reference_sample = "2b507e0ad4515d9d47fb7f0bfa1f1eb11de25db4fca49fc1417ea991dc33b6bf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 54 20 52 45 53 45 41 52 43 48 2C 20 49 4E 43 2E 20 54 41 49 57 41 4E 20 42 52 41 4E 43 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 6F 00 6D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "iomem.pdb"
        $str2 = "iomem.sys" wide
        $str3 = "DTR Kernel mode driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}