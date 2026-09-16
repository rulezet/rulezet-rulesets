rule Linux_Trojan_Zerobot_3a5b56dd {
    meta:
        author = "Elastic Security"
        id = "3a5b56dd-e829-44bb-ae70-d7001addd057"
        fingerprint = "9800a241ab602434426830110ce244cdfd0023176e5fa64e2b8761234ed6f529"
        creation_date = "2022-12-16"
        last_modified = "2024-02-13"
        description = "Strings found in the Zerobot Spoofed Header method"
        threat_name = "Linux.Trojan.Zerobot"
        reference_sample = "f9fc370955490bdf38fc63ca0540ce1ea6f7eca5123aa4eef730cb618da8551f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $HootSpoofHeader_0 = "X-Forwarded-Proto: Http"
        $HootSpoofHeader_1 = "X-Forwarded-Host: %s, 1.1.1.1"
        $HootSpoofHeader_2 = "Client-IP: %s"
        $HootSpoofHeader_3 = "Real-IP: %s"
        $HootSpoofHeader_4 = "X-Forwarded-For: %s"
    condition:
        3 of them
}