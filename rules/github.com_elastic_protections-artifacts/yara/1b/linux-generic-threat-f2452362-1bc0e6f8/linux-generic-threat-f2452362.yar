rule Linux_Generic_Threat_f2452362 {
    meta:
        author = "Elastic Security"
        id = "f2452362-dc55-452f-9e93-e6a6b74d8ebd"
        fingerprint = "cc293c87513ca1332e5ec13c9ce47efbe5e9c48c0cece435ac3c8bdbc822ea82"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5ff46c27b5823e55f25c9567d687529a24a0d52dea5bc2423b36345782e6b8f6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 6F 72 69 67 69 6E 61 6C 5F 72 65 61 64 64 69 72 }
        $a2 = { 45 72 72 6F 72 20 69 6E 20 64 6C 73 79 6D 3A 20 25 73 }
    condition:
        all of them
}