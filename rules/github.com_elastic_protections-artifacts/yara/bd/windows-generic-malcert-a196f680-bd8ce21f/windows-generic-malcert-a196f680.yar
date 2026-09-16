rule Windows_Generic_MalCert_a196f680 {
    meta:
        author = "Elastic Security"
        id = "a196f680-63d3-4cae-94fa-c9a56b782ef8"
        fingerprint = "81f1b0be9b876c7f729d810c9a51777147fdf251a55cd91bee3bf304ec595ad9"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "45fdcd215d2dec931b4136c3b6f4807d53db7a0e1466bbb1afc9d68e872053d3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 2E DD 68 6F FF 3B 20 4C C4 23 16 73 FA CE AC 92 }
    condition:
        all of them
}