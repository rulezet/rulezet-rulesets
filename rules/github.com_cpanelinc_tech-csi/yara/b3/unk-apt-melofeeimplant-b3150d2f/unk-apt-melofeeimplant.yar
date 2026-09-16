rule UNK_APT_MelofeeImplant {
    meta:
        author = "Exatrack"
        date =   "2023-03-03"
        update =   "2023-03-03"
        description = "Detects the Melofee implant"
        tlp =  "CLEAR"
        sample_hash = "a5a4284f87fd475b9474626040d289ffabba1066fae6c37bd7de9dabaf65e87a,f3e35850ce20dfc731a6544b2194de3f35101ca51de4764b8629a692972bef68,8d855c28744dd6a9c0668ad9659baf06e5e448353f54d2f99beddd21b41390b7"

    strings:
        $str_melofee_implant_01 = "10PipeSocket"
        $str_melofee_implant_02 = "ikcp_ack_push"
        $str_melofee_implant_03 = "TLSSocketEE"
        $str_melofee_implant_04 = "/tmp/%s.lock"
        $str_melofee_implant_05 = "neosmart::WaitForMultipleEvents"
        $str_melofee_implant_06 = "9TLSSocket"
        $str_melofee_implant_07 = "7VServer"
        $str_melofee_implant_08 = "N5boost6detail13sp_ms_deleterI13UdpSocketWrapEE"
        $str_melofee_implant_09 = "UdpServerWrap"
        $str_melofee_implant_10 = "KcpUpdater"
        $str_melofee_implant_11 = "SelfForwardServer"

        $str_command_parsing_01 = {3? 01 00 05 00 ?? ?? ?? ?? 00 00 3? 01 00 05 00 ?? ?? 3? 05 00 04 00}
        $str_command_parsing_02 = {3? 04 00 04 00 ?? ?? ?? ?? 00 00 3? 04 00 04 00 ?? ?? 3? 05 00 01 00}
        $str_command_parsing_03 = {3? 01 00 07 00 ?? ?? ?? ?? 00 00 3? 01 00 09 00 ?? ?? ?? ?? ?? 00 3? 01 00 06 00 }

    condition:
        3 of them
}