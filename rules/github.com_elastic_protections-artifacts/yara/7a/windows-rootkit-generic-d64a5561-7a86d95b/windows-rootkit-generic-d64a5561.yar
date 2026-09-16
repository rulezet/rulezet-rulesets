rule Windows_Rootkit_Generic_d64a5561 {
    meta:
        author = "Elastic Security"
        id = "d64a5561-7f00-4ee5-9f9b-3913bcee6dbd"
        fingerprint = "ed0cb8fd06ca3b084737f0ada26c9949f40b75b721d7f7d193a8436ecf8d8e4f"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: WDKTestCert youss,133730752550224793"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "7ccb02b9dc8bb46e5ea32fb8f4c93bac195bcbb0c2fc02d3af28f4208afe7c41"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 79 6F 75 73 73 2C 31 33 33 37 33 30 37 35 32 35 35 30 32 32 34 37 39 33 }
        $str1 = "D:\\Games\\YoussiLovesPenis\\Kinkajou\\x64\\Release\\Kinkajou.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}