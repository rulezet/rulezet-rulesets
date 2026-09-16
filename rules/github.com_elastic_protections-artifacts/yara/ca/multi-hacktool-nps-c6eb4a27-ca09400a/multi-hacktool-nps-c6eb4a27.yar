rule Multi_Hacktool_Nps_c6eb4a27 {
    meta:
        author = "Elastic Security"
        id = "c6eb4a27-c481-41b4-914d-a27d10672d30"
        fingerprint = "1386e4cef0f347b38a4614311d585b0b83cb9526b19215392aee893e594950de"
        creation_date = "2024-01-24"
        last_modified = "2024-01-29"
        threat_name = "Multi.Hacktool.Nps"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        reference_sample = "4714e8ad9c625070ca0a151ffc98d87d8e5da7c8ef42037ca5f43baede6cfac1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str_info0 = "Reconnecting..."
        $str_info1 = "Loading configuration file %s successfully"
        $str_info2 = "successful start-up of local socks5 monitoring, port"
        $str_info3 = "successful start-up of local tcp monitoring, port"
        $str_info4 = "start local file system, local path %s, strip prefix %s ,remote port %"
        $str_info5 = "start local file system, local path %s, strip prefix %s ,remote port %s"
    condition:
        all of them
}