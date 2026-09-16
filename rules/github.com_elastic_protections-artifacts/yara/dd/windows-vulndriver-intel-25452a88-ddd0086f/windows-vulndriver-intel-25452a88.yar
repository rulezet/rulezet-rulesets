rule Windows_VulnDriver_Intel_25452a88 {
    meta:
        author = "Elastic Security"
        id = "25452a88-82c2-420a-81f4-ee7778c2eccf"
        fingerprint = "ead0cd4385e17032ed229a87432875d6e497a783349fec55f3a5c30ecaa5dfff"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PAIPTAC  Driver"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "82b30461dbf40ac15fce6a83b9bad2ebd05b27dea1b784eaa096422fe8927b7b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 41 49 50 54 41 43 20 20 44 72 69 76 65 72 }
        $str1 = "pmxdrv32e.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}