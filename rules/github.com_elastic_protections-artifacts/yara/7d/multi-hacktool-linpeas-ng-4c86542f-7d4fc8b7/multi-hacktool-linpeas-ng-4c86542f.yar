rule Multi_Hacktool_LinPEAS_ng_4c86542f {
    meta:
        author = "Elastic Security"
        id = "4c86542f-ca54-4bdb-a91a-faee83a0e7ac"
        fingerprint = "b2d75cc3f187a00b85c092dc683e9efee6f116f02e1cbc5296402f42fd328436"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Network info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $network_0 = "Hostname, hosts and DNS" base64
        $network_1 = "Networks and neighbours" base64
        $network_2 = "(route || ip n || cat /proc/net/route)" base64
        $network_3 = "networksetup -listallhardwareports" base64
        $network_4 = "timeout 1 tcpdump >/dev/null" base64
        $network_5 = "[-] No ifconfig or ip commands" base64
        $network_6 = "$(netstat -na | grep LISTEN | grep tcp46 | grep \"*.3283\" | wc -l);" base64
        $network_7 = "The following services are OFF if" base64
        $network_8 = "s,Password|Authorization Name.*" base64
        $network_9 = "host.docker.internal" base64
    condition:
        5 of them
}