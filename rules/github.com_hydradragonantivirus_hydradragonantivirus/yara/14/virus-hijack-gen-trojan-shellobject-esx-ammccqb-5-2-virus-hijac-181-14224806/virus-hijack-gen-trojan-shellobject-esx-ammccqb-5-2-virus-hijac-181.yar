import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_181 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
    hash3       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $x1  = "!!!!!fuk-tcpa!!!!!<?xml version=\"1.0\" encoding=\"utf-8\"?><Rules xmlns=\"urn:Rules\"><Rule RuleId=\"1000\" RuleVersion=\"5\" D" ascii
    $s2  = "ystemProductId\" MissingFieldHandling=\"Ignore\" /></UnaryOperator></Column><Triggers><Source Token=\"2\" /></Triggers></Rule><R" ascii
    $s3  = "n><Column OutType=\"WSTRING\" Index=\"15\" Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessFileName\" MissingFieldHandling=" ascii
    $s4  = "gFieldHandling=\"Ignore\" /></Column><Column OutType=\"WSTRING\" Index=\"15\" Nullable=\"true\"><Source Token=\"1\" Field=\"Proc" ascii
    $s5  = "rce Token=\"1\" /></Triggers></Rule><Rule RuleId=\"270006\" RuleVersion=\"3\" DataClassifications=\"SM\" Target=\"Upload\" xmlns" ascii
    $s6  = "NG\" Index=\"9\" Nullable=\"false\"><Source Token=\"2\" Field=\"ProcessFileName\" /></Column><Column OutType=\"BOOL\" Index=\"10" ascii
    $s7  = "ngFieldHandling=\"Ignore\" /></Column><Column OutType=\"UINT32\" Index=\"5\" Nullable=\"true\"><Source Token=\"1\" Field=\"Proce" ascii
    $s8  = "0108\" RuleVersion=\"5\" DataClassifications=\"ESM\" Target=\"Upload\" xmlns=\"\"><Sources><RuleSource Token=\"1\" RuleId=\"1201" ascii
    $s9  = " Token=\"3\" /></Triggers></Rule><Rule RuleId=\"170054\" RuleVersion=\"1\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"" ascii
    $s10 = "nInitTime\" /></Column><Column OutType=\"GUID\" Index=\"2\" Nullable=\"false\"><Source Token=\"1\" Field=\"CrashedProcessSession" ascii
    $s11 = "\"WSTRING\" Index=\"0\" Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessorArchitecture\" MissingFieldHandling=\"Ignore\" />" ascii
    $s12 = "riggers><Source Token=\"1\" /></Triggers></Rule><Rule RuleId=\"270007\" RuleVersion=\"0\" DataClassifications=\"SM\" Target=\"Up" ascii
    $s13 = "ex=\"13\" Nullable=\"false\"><Source Token=\"3\" Field=\"ProcessorArchitecture\" /></Column><Column OutType=\"UINT32\" Index=\"1" ascii
    $s14 = "lumn OutType=\"UINT32\" Index=\"1\" Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessorCount\" MissingFieldHandling=\"Ignore" ascii
    $s15 = "Rule RuleId=\"120107\" RuleVersion=\"5\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"><Sources><ULSTagSource Token=\"" ascii
    $s16 = "Triggers><Source Token=\"1\" /></Triggers></Rule><Rule RuleId=\"360001\" RuleVersion=\"2\" DataClassifications=\"SM\" Target=\"U" ascii
    $s17 = "=\"false\"><Source Token=\"3\" Field=\"ProcessorCount\" /></Column><Column OutType=\"UINT32\" Index=\"15\" Nullable=\"true\"><So" ascii
    $s18 = "Target=\"Subrule\" xmlns=\"\"><Sources><Timer Token=\"1\" Interval=\"30s\" /><AppEvent Token=\"2\" Event=\"TelemetryResume\" /><" ascii
    $s19 = "iggers><Starts><Source Token=\"1\" /></Starts></Rule><Rule RuleId=\"120124\" RuleVersion=\"0\" DataClassifications=\"ESM\" Targe" ascii
    $s20 = "<Rule RuleId=\"120300\" RuleVersion=\"3\" DataClassifications=\"SM\" Target=\"Subrule\" xmlns=\"\"><Sources><ULSAllCategoriesSou" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}