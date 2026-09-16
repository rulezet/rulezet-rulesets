rule Windows_Generic_MalCert_728e5383 {
    meta:
        author = "Elastic Security"
        id = "728e5383-4c0e-47ee-ac69-9d6cf32a12cd"
        fingerprint = "b0401c8c080096af14ff86ac60d406b7359b06f67514e0fd7d0b4cb7b1022219"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "a4a1956522fefb1fd56af705b139320f39b0a5964d8d66c2c0bc6676dacd3983"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 DD 67 00 A6 3F D6 D3 A2 CF F5 F8 AC 95 54 FC 4A }
    condition:
        all of them
}