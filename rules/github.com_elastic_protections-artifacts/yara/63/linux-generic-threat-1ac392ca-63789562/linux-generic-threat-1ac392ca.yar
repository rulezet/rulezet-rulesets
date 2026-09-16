rule Linux_Generic_Threat_1ac392ca {
    meta:
        author = "Elastic Security"
        id = "1ac392ca-d428-47ef-98af-d02d8305ae67"
        fingerprint = "e21805cc2d548c940b0cefa8ee99bd55c5599840e32b8341a4ef5dfb0bc679ff"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "dca2d035b1f7191f7876eb727b13c308f63fe8f899cab643526f9492ec0fa16f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 53 4F 41 50 41 63 74 69 6F 6E 3A 20 75 72 6E 3A 73 63 68 65 6D 61 73 2D 75 70 6E 70 2D 6F 72 67 3A 73 65 72 76 69 63 65 3A 57 41 4E 49 50 43 6F 6E 6E 65 63 74 69 6F 6E 3A 31 23 41 64 64 50 6F 72 74 4D 61 70 70 69 6E 67 }
    condition:
        all of them
}