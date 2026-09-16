rule Multi_Trojan_Mythic_528324b4 {
    meta:
        author = "Elastic Security"
        id = "528324b4-822d-4e48-b4ab-f5b234348773"
        fingerprint = "5188aa792c02acf7a6346f395389390ae187cb08083bfca27283a4f4dd4d7206"
        creation_date = "2024-05-23"
        last_modified = "2024-06-12"
        threat_name = "Multi.Trojan.Mythic"
        reference_sample = "2cd883eab722a5eacbca7fa82e0eebb5f6c30cffa955abcb1ab8cf169af97202"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $import1 = "Autofac"
        $import2 = "Obfuscar"
        $import3 = "Agent.Profiles.Http"
        $import4 = "Agent.Managers.Linux"
        $import5 = "Agent.Managers.Reflection"
        $athena1 = "Athena.Commands.dll"
        $athena2 = "Athena.Handler.Linux.dll"
        $athena3 = "Athena.dll"
        $athena4 = "Athena.Profiles.HTTP.dll"
    condition:
        (2 of ($import*)) or (2 of ($athena*))
}