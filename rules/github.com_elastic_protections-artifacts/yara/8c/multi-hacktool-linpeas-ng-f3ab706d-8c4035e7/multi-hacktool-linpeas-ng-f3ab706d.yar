rule Multi_Hacktool_LinPEAS_ng_f3ab706d {
    meta:
        author = "Elastic Security"
        id = "f3ab706d-1ad4-4ff2-a461-f877c7990dbb"
        fingerprint = "a41a8ff83d1c94b63fb1ecbeded1e54b7d93fb4698ed8dda01b122d1f328de36"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the systen information module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cve_0 = "CVEs Check"
        $cve_1 = "Vulnerable to CVE-2021-4034"
        $cve_2 = "Vulnerable to CVE-2021-3560"
        $cve_3 = "Potentially Vulnerable to CVE-2022-0847"
        $cve_4 = "Potentially Vulnerable to CVE-2022-2588"
        $cpu_0 = "Any sd*/disk* disk in /dev?"
        $cpu_1 = "$(command -v diskutil)"
        $cpu_2 = "Mounted disks information"
        $cpu_3 = "$(command -v smbutil)"
        $protections_0 = "grsecurity present?"
        $protections_1 = "AppArmor enabled?"
        $protections_2 = "User namespace?"
        $protections_3 = "XProtectPlistConfigData"
    condition:
        (2 of ($cve_*) and 2 of ($cpu_*) and 2 of ($protections_*))
}