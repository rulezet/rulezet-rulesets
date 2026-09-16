rule Windows_Generic_MalCert_08e6d68d {
    meta:
        author = "Elastic Security"
        id = "08e6d68d-2316-4060-9739-c4376906e0f8"
        fingerprint = "f463b04d044f8b58fdc77541aa3655138cdae6ad4ea460bb293c37826968da66"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "19d900ffefd8639dee4d351404e06f47852771e8d2544515776cc1abec4dcecc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 40 CE 44 CE DB 44 70 A1 40 31 F6 E1 }
    condition:
        all of them
}