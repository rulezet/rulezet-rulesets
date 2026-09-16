rule Windows_VulnDriver_Asus_1d4d083e {
    meta:
        author = "Elastic Security"
        id = "1d4d083e-1631-460d-bd48-2d736b612518"
        fingerprint = "2e6af17c557184e4719d230dffca60fbaa3c77d67af1ed0585c9f68da083108e"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 0.2.2.3"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "fb6b0d304433bf88cc7d57728683dbb4b9833459dc33528918ead09b3907ff22"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x02][\x00-\x00][\x02-\x02][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "ATSZIO64.pdb"
        $str2 = "ATSZIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}