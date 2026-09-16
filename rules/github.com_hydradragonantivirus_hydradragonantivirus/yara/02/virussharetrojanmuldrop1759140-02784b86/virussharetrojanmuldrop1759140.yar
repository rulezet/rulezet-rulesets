rule VirusShareTrojanMulDrop1759140 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanMulDrop1759140.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf0394b1aa18e631b2321e829ca2e7818a5336307b7d137e6e2e03e5bc86a82d"

  strings:
    $s1  = "Error dumping Object." fullword wide
    $s2  = "Reference not allowed here, use & where possible. Only %A_AhkPath% %A_AhkDir% %A_DllPath% %A_DllDir% %A_ScriptDir% %A_AppData[Co" wide
    $s3  = "  -  Press yes to exit thread and continue execution." fullword wide
    $s4  = "<response command=\"typemap_get\" transaction_id=\"%e\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http" ascii
    $s5  = "<response command=\"typemap_get\" transaction_id=\"%e\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http" ascii
    $s6  = "<response command=\"feature_get\" feature_name=\"%e\" supported=\"%i\" transaction_id=\"%e\">%s</response>" fullword ascii
    $s7  = "This script requires %s%s." fullword wide
    $s8  = "This line will never execute, due to %s preceeding it." fullword wide
    $s9  = "<response command=\"%s\" transaction_id=\"%e\"/>" fullword ascii
    $s10 = "<response command=\"stack_depth\" depth=\"%i\" transaction_id=\"%e\"/>" fullword ascii
    $s11 = "     - Prevent the Program Compatibility Assistant from popping up if Windows" fullword ascii
    $s12 = "<response command=\"breakpoint_set\" transaction_id=\"%e\" state=\"%s\" id=\"%i\"/>" fullword ascii
    $s13 = "<response command=\"context_get\" context=\"%i\" transaction_id=\"%e\">" fullword ascii
    $s14 = "<response command=\"%s\" status=\"%s\" reason=\"%s\" transaction_id=\"%e\"/>" fullword ascii
    $s15 = "<response command=\"%s\" transaction_id=\"%e" fullword ascii
    $s16 = "<response command=\"status\" status=\"%s\" reason=\"ok\" transaction_id=\"%e\"/>" fullword ascii
    $s17 = "<response command=\"feature_set\" feature=\"%e\" success=\"%i\" transaction_id=\"%e\"/>" fullword ascii
    $s18 = "<response command=\"property_set\" success=\"%i\" transaction_id=\"%e\"/>" fullword ascii
    $s19 = "<response command=\"%s\" success=\"1\" transaction_id=\"%e\"/>" fullword ascii
    $s20 = "Could not commit memory for DllImport." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}