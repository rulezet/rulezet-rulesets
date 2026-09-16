rule win_quasarrat_j2 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "detects the Quasar RAT"

    strings:
        $str_1 = "get_usernameField" ascii
        $str_2 = "get_timePasswordChanged" ascii
        $str_3 = "get_encryptedUsername" ascii
        $str_4 = "get_encryptedPassword" ascii
        $str_5 = "get_VistaOrHigher" ascii
        $str_6 = "get_UseProtoMembersOnly" ascii
        $str_7 = "get_UseImplicitZeroDefaults" ascii
        $str_8 = "get_TenOrHigher" ascii
        $str_9 = "get_MetadataTimeoutMilliseconds" ascii
        $str_10 = "get_EightPointOneOrHigher" ascii
        $str_11 = "get_EightOrHigher" ascii
        $str_12 = "get_DynamicType" ascii

        $quasar = "Quasar.Client.Properties.Resources" wide

        condition:
            uint16(0) == 0x5A4D and 
            8 of ($str_*) and $quasar
}