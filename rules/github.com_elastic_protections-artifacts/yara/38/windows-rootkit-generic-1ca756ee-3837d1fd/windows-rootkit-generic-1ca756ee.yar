rule Windows_Rootkit_Generic_1ca756ee {
    meta:
        author = "Elastic Security"
        id = "1ca756ee-e9f8-405e-8a39-3b4caed4347b"
        fingerprint = "63bdd69245d668a9d4682afd21418049bfc16a35c711bfa85a89529107bcfdba"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: WDKTestCert yo,133912822835426319"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "f5dd6db447868c2964c1d109e7d2cc31ebdace198b3d0a02cfba5b7ef7ae6964"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 79 6F 2C 31 33 33 39 31 32 38 32 32 38 33 35 34 32 36 33 31 39 }
        $str1 = "C:\\Users\\Public\\wtf.pdb"
        $str2 = "\\DosDevices\\Kinkajou" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}