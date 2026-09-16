rule Windows_VulnDriver_Supermicro_350147cf {
    meta:
        author = "Elastic Security"
        id = "350147cf-acea-4650-97ff-f927647de5fe"
        fingerprint = "d938406d1a7dac79e74248fa3e946251edc533c0dde008605774173ccc1fd068"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Super Micro Computer, Inc."
        threat_name = "Windows.VulnDriver.Supermicro"
        reference_sample = "a6f8aa3de5b4aea58eddd45807d722c864d4bc4a38ad573174af864e21f0d526"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 75 70 65 72 20 4D 69 63 72 6F 20 43 6F 6D 70 75 74 65 72 2C 20 49 6E 63 2E }
        $str1 = "superbmc.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}