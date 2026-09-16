rule Windows_VulnDriver_Avast_dac4c6be {
    meta:
        author = "Elastic Security"
        id = "dac4c6be-eaa6-435a-9028-589abef3c105"
        fingerprint = "a497f7c04c6b573ae2505b95dfb3bb5beebb073375a3ddc87daff4c435c45b4c"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software s.r.o., Version: <= 19.7.4246.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "dcb815eb8e9016608d0d917101b6af8c84b96fb709dc0344bceed02cbc4ed258"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0f]|[\x00-\x95][\x10-\x10])|[\x07-\x07][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\x00][\x00-\x00][\x96-\x96][\x10-\x10])/
        $str1 = "aswArPot.pdb"
        $str2 = "Avast Antivirus " wide
        $str3 = "Avast anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}