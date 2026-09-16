rule Windows_Trojan_Smokeloader_62eb5427 {
    meta:
        author = "Elastic Security"
        id = "62eb5427-0488-4c6c-aefc-00f4120bd2a9"
        fingerprint = "eb9b8149997deb5701c51d6cac58e03a111c23cba2cc1bb4abcfaa56f201cc08"
        creation_date = "2024-08-27"
        last_modified = "2024-09-30"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "21e7fcce8ffb7826108800b6aee21d6b8ea9275975b639ed5ca9f8ddd747329e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C7 45 FC 00 00 00 00 8B 45 08 03 40 3C 8B 40 78 03 45 08 50 8B 48 18 8B 50 20 03 55 08 }
        $b = { 8B 7D F4 89 F1 B8 19 04 00 00 F2 66 AF }
        $c = { C7 44 05 D0 53 6C 65 65 8B 45 C8 83 C0 04 89 45 C8 }
    condition:
        any of them
}