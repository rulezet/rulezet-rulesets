rule Windows_VulnDriver_Intel_84f3973f {
    meta:
        author = "Elastic Security"
        id = "84f3973f-f8a4-48b8-aa91-72154f627fa3"
        fingerprint = "95f1d823d1d308f5becb15a989ef592b9b77fcf76e6905ab8362c0c2c3d776a8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Software Development Products"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "17f19350ea6715ce94ca2014bce92a5c07fd752fd06647a8200db6b052468810"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 53 6F 66 74 77 61 72 65 20 44 65 76 65 6C 6F 70 6D 65 6E 74 20 50 72 6F 64 75 63 74 73 }
        $str1 = "sepdrv3_15.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}