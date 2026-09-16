rule Windows_Generic_MalCert_2b11268a {
    meta:
        author = "Elastic Security"
        id = "2b11268a-566f-48ad-9a96-dc075a02297b"
        fingerprint = "027c2fcf99ce15c2707505d0939b3826342cce9614dba5073db1c4a68fe39f99"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "4a13f40561173347308fa4da0767af4244e899077b6e609805d61742fdea5363"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0F 1D 3B 26 EA 4F FB F7 73 10 2C 4E D8 A9 8D 70 }
    condition:
        all of them
}