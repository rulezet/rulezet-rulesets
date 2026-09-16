rule Windows_VulnDriver_Intel_ddc245ff {
    meta:
        author = "Elastic Security"
        id = "ddc245ff-7137-43a6-a8c6-b60081c776b3"
        fingerprint = "0a0626bbafc093236289a87ca756aeae7afabed983ce334ab43659546225ccbc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 1.3.0.7"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "iqvw64e.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}