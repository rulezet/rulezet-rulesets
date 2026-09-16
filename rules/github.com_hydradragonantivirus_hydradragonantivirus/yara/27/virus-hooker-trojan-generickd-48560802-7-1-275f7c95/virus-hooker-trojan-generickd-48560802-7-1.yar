rule Virus_Hooker_Trojan_GenericKD_48560802_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48560802_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8d23f250c6da6d74b40c5ccfcb41e0561e43e040a399ffbdfb741b4e987b360"

  strings:
    $s1  = "            Process[] minr = Process.GetProcessesByName(\"hostdl\");" fullword ascii
    $s2  = "miner=new Process();" fullword ascii
    $s3  = "Process miner;" fullword ascii
    $s4  = "NULL SHIELD - 866423101923473508827272152" fullword ascii
    $s5  = "NULL SHIELD - 551480035536456033521521882" fullword ascii
    $s6  = "[assembly: AssemblyTitle(\"Antimalware service executable\")]" fullword ascii
    $s7  = "[assembly: AssemblyProduct(\"Antimalware service executable\")]" fullword ascii
    $s8  = "Windows service controller" fullword wide
    $s9  = "public static string CurDir=\"\";" fullword ascii
    $s10 = "Supreme" fullword ascii
    $s11 = "            string appdata = CurDir;" fullword ascii
    $s12 = "                    File.Copy(copy, appdata);" fullword ascii
    $s13 = "[assembly: AssemblyCompany(\"Microsoft Corporation\")]" fullword ascii
    $s14 = "Copyright 2018" fullword wide
    $s15 = "stawP5egcc2xvF7<Module>" fullword ascii
    $s16 = "2IdT1yKnlRAtw8c<Module>" fullword ascii
    $s17 = "a5AHMrk9jgqx66O<Module>" fullword ascii
    $s18 = "uuqws4EohN<Module>" fullword ascii
    $s19 = "GEoCg6CSmS<Module>" fullword ascii
    $s20 = "rsdRpxfcKb<Module>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}