rule Windows_Generic_MalCert_577c572d {
    meta:
        author = "Elastic Security"
        id = "577c572d-704a-4fda-9d4c-d2ce9400ac5d"
        fingerprint = "f6ccc743e6927fb0580a3c60a4ebc46a0f00335ac13325727759595b1659187b"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "a941413f86e84dfe14f1ef161ff0677971359fd5992f5463965e5754aca6115c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 4F AF 34 C6 62 37 73 26 A5 85 FD 91 02 8C 65 76 }
    condition:
        all of them
}