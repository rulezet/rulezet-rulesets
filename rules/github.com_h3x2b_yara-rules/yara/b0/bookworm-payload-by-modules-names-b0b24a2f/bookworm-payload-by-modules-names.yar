rule bookworm_payload_by_modules_names : malware
{
    meta:
         description = "Detect ushata payload by usage of more than 2 modules"
         author = "@h3x2b <tracker _AT h3x.eu>"

    strings:
        $mod_01 = "Leader.dll"
        $mod_02 = "Coder.dll"
        $mod_03 = "Digest.dll"
        $mod_04 = "AES.dll"
        $mod_05 = "KBLogger.dll"
        $mod_06 = "Network.dll"
        $mod_07 = "Resolver.dll"
        $mod_08 = "HTTP.dll"
        $mod_09 = "WinINetwork.dll"
        $mod_10 = "ushata.dll"
        $mod_11 = "ProgramStartup"

    condition:
        3 of them

}