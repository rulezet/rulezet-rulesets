rule dotnet_libraries: info compiler dotnet
{
    meta:
                description = ".Net runtime mscoree.dll mscorwks.dll"

    strings:
        $str_dn_01 = "mscoree.dll"
        $str_dn_02 = "_CorExeMain"
        $str_dn_03 = "_CorDllMain"
        $str_dn_04 = "mscorwks.dll"
        $str_dn_05 = "CoInitializeEE"

    condition:
        2 of ($str_dn_* )

}