rule Windows_VulnDriver_Asus_25621f13 {
    meta:
        author = "Elastic Security"
        id = "25621f13-ddaa-475c-ab1c-da9ed8bfde21"
        fingerprint = "155f9965273e3edfe33b9166e5e64c73e717e5de637487a40a7f9a5a060ac03e"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "218de0c801b70d8bebf0233f796de07842b84b899c49f7a7be1c0423a158b786"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $str1 = "AsIO3_32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}