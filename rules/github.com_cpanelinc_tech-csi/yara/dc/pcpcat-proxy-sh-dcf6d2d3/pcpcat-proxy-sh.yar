rule PCPcat_proxy_sh {
    meta:
        description = "PCPcat proxy.sh installer"
    strings:
        $s1 = "pcpcat-gost.service"
        $s2 = "pcpcat-frp.service"
        $s3 = "67.217.57.240:888"
        $s4 = "FRP_VERSION"
    condition:
        3 of them
}