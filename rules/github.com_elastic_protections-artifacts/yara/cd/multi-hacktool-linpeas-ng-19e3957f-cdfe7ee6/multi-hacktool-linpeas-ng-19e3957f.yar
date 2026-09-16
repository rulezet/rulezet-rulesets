rule Multi_Hacktool_LinPEAS_ng_19e3957f {
    meta:
        author = "Elastic Security"
        id = "19e3957f-8f44-47e1-abf8-a40de645594e"
        fingerprint = "c2e952348ce89a802cedcb089bb1306d3f8f077262753133a35b7a18f8711ba8"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the systen information module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cve_0 = "CVEs Check" base64
        $cve_1 = "Vulnerable to CVE-2021-4034" base64
        $cve_2 = "Vulnerable to CVE-2021-3560" base64
        $cve_3 = "Potentially Vulnerable to CVE-2022-0847" base64
        $cve_4 = "Potentially Vulnerable to CVE-2022-2588" base64
        $cpu_0 = "Any sd*/disk* disk in /dev?" base64
        $cpu_1 = "$(command -v diskutil)" base64
        $cpu_2 = "Mounted disks information" base64
        $cpu_3 = "$(command -v smbutil)" base64
        $protections_0 = "grsecurity present?" base64
        $protections_1 = "AppArmor enabled?" base64
        $protections_2 = "User namespace?" base64
        $protections_3 = "XProtectPlistConfigData" base64
    condition:
        (2 of ($cve_*) and 2 of ($cpu_*) and 2 of ($protections_*))
}