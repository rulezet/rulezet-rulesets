rule Windows_Ransomware_Nefilim_3969d6a7 {
    meta:
        author = "Elastic Security"
        id = "3969d6a7-4601-4bf1-8434-a0f48e93c7c4"
        fingerprint = "734c8802f201052c2c29c6905a2a222eec592f913a3b65e0daf2af2e53ea3eb0"
        creation_date = "2026-07-08"
        last_modified = "2026-07-15"
        threat_name = "Windows.Ransomware.Nefilim"
        reference_sample = "0bafde9b22d7147de8fdb852bcd529b1730acddc9eb71316b66c180106f777f5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "NEF1LIM"
        $b = "-DECRYPT.txt"
        $c = "main.BytesToPublicKey"
    condition:
        all of them
}