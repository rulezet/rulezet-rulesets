rule Windows_Generic_MalCert_45f72bf1 {
    meta:
        author = "Elastic Security"
        id = "45f72bf1-d065-4a84-bdb3-0598a704571a"
        fingerprint = "5362db78002b1ebd5ca65e3a22a43d8c789d31e6e60089643e3fa9feb5774b95"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "79b6e63218982c1e85a5e1798c5484e7e034cfecbe9f2da604f668fda8428af4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 69 C5 54 75 FF D7 B1 A2 47 42 96 E1 4C 5C F8 D9 }
    condition:
        all of them
}