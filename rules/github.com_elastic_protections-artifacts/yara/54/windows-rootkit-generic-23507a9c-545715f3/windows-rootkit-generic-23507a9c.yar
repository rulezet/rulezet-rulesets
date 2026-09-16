rule Windows_Rootkit_Generic_23507a9c {
    meta:
        author = "Elastic Security"
        id = "23507a9c-7001-4888-befe-cc3556138b98"
        fingerprint = "89d66fdbfc41c9f7bb87243056b642f20e5f0a71d8b54885dd12942e2acf6865"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "575e58b62afab094c20c296604dc3b7dd2e1a50f5978d8ee24b7dca028e97316"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "\\code\\[2-5]fileopr\\objfre_win7_amd64\\amd64\\MyDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}