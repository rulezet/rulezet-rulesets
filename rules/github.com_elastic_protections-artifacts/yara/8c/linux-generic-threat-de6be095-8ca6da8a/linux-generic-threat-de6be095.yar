rule Linux_Generic_Threat_de6be095 {
    meta:
        author = "Elastic Security"
        id = "de6be095-93b6-45da-b9e2-682cea7a6488"
        fingerprint = "8f2d682401b4941615ecdc8483ff461c86a12c585483e00d025a1b898321a585"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2431239d6e60ca24a5440e6c92da62b723a7e35c805f04db6b80f96c8cf9fee6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2D 2D 66 61 72 6D 2D 66 61 69 6C 6F 76 65 72 }
        $a2 = { 2D 2D 73 74 72 61 74 75 6D 2D 66 61 69 6C 6F 76 65 72 }
    condition:
        all of them
}