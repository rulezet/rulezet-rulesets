rule Multi_Hacktool_LinPEAS_ng_f9a55fb7 {
    meta:
        author = "Elastic Security"
        id = "f9a55fb7-e457-4b39-943d-a4f99d3a93bf"
        fingerprint = "ffbb559253e242fed1881027e59519a5debe1095237d6efcac5604dd4ac2d2c5"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Network info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $network_0 = "Hostname, hosts and DNS"
        $network_1 = "Networks and neighbours"
        $network_2 = "(route || ip n || cat /proc/net/route)"
        $network_3 = "networksetup -listallhardwareports"
        $network_4 = "timeout 1 tcpdump >/dev/null"
        $network_5 = "[-] No ifconfig or ip commands"
        $network_6 = "$(netstat -na | grep LISTEN | grep tcp46 | grep \"*.3283\" | wc -l);"
        $network_7 = "The following services are OFF if"
        $network_8 = "s,Password|Authorization Name.*"
        $network_9 = "host.docker.internal"
    condition:
        5 of them
}