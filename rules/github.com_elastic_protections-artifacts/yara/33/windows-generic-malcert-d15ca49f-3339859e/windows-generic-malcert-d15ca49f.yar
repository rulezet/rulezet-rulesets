rule Windows_Generic_MalCert_d15ca49f {
    meta:
        author = "Elastic Security"
        id = "d15ca49f-7571-45cd-b162-37872075a271"
        fingerprint = "1bbab9e46fbb7f4545c01557b62f428a38009421472e19498766884d65757f66"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e912bb10a2371ab0f884cd38bf2940e056f6d2e4aea4010303e98a7a5edcfcbf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 71 AC D1 EC EB 75 F9 2B DC CB DB 9E F3 6F DD EC }
    condition:
        all of them
}