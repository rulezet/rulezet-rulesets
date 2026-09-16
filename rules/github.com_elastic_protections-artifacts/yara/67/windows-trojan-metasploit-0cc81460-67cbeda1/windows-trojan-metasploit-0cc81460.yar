rule Windows_Trojan_Metasploit_0cc81460 {
    meta:
        author = "Elastic Security"
        id = "0cc81460-f4bf-4f7d-952d-49396ac0d3e0"
        fingerprint = "96651309f4b9b1643cf49086411562510182a9b777b167ff64792734df2eb294"
        creation_date = "2025-05-02"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = /\x64\x8B\x52\x30.{1,30}\x7C\x02\x2C\x20\xC1\xCF\x0D.{40,80}\x75\xF4\x03\x7D\xF8\x3B\x7D\x24\x75\xE0/
    condition:
        all of them
}