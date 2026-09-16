rule Windows_Generic_MalCert_234b63fb {
    meta:
        author = "Elastic Security"
        id = "234b63fb-8f9c-41c5-8b74-d145caebf855"
        fingerprint = "40845cbe09195aca9f7e20c5adb421b5c3afb7341d2d8f9f73bdca942e82d9e3"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "bd699b1213d86f2d1d35f79bd74319d24df1c77cdef5c010720dfb290d0c74f2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 51 E1 5E FC 91 6D A7 06 BF E8 47 36 6E 5C AF CB }
    condition:
        all of them
}