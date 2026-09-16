rule Windows_VulnDriver_Asus_308741d3 {
    meta:
        author = "Elastic Security"
        id = "308741d3-cc20-4709-9de5-262e75a42636"
        fingerprint = "e52e88840392901254b714ff9bdb4acfd3aac15bb1ccef61d9aee0205ba68906"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "2d195cd4400754cc6f6c3f8ab1fe31627932c3c1bf8d5d0507c292232d1a2396"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $str1 = "AsIO3_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}