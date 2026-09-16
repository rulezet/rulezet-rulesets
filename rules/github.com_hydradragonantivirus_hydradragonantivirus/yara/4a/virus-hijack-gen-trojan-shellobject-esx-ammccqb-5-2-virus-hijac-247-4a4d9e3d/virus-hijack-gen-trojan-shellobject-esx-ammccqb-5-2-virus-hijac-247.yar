import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_247 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "94143e3c5b8bf576088fbdd4f8e39dabb3fa3deb0d3e54c9f019a0c50027f333"
    hash3       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
    hash4       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $s1  = "llMeD_ExecutedCommand\" OutType=\"WSTRING\" /></Column><Column OutType=\"WSTRING\" Index=\"10\" Nullable=\"true\"><Source Token=" ascii
    $s2  = "><Right><Source Token=\"1\" Field=\"ExtraProcessingLimit\" /></Right></Operator></Filter><ThisRule Token=\"4\" /></Sources><Colu" ascii
    $s3  = "eNoError\"><Source Token=\"1\" Field=\"ExtraProcessingLimit\" MissingFieldHandling=\"Ignore\" /></Column><Triggers><Source Token" ascii
    $s4  = "Target=\"Upload\" xmlns=\"\"><Sources><ULSTagSource Token=\"1\" StringTagId=\"dasij\" /></Sources><Column OutType=\"GUID\" Index" ascii
    $s5  = "s><Source Token=\"1\" /></Triggers></Rule><Rule RuleId=\"68009\" RuleVersion=\"0\" DataClassifications=\"SM\" Target=\"Upload\" " ascii
    $s6  = "urce Token=\"3\" /></Triggers></Rule><Rule RuleId=\"68004\" RuleVersion=\"13\" DataClassifications=\"SM\" Target=\"Upload\" xmln" ascii
    $s7  = "n><Triggers><Source Token=\"1\" /></Triggers></Rule><Rule RuleId=\"68014\" RuleVersion=\"8\" DataClassifications=\"SM\" Target=" ascii
    $s8  = "e><Rule RuleId=\"68006\" RuleVersion=\"0\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"><Sources><ULSTagSource Token=" ascii
    $s9  = "<Rule RuleId=\"68010\" RuleVersion=\"1\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"><Sources><ULSTagSource Token=\"" ascii
    $s10 = "urce Token=\"1\" Field=\"executedControlTcid\" MissingFieldHandling=\"Ignore\" /></Column><Column OutType=\"UINT32\" Index=\"8\"" ascii
    $s11 = "ule><Rule RuleId=\"68000\" RuleVersion=\"2\" DataClassifications=\"SM\" Target=\"Subrule\" xmlns=\"\"><Sources><ULSTagSource Tok" ascii
    $s12 = "</Triggers><Starts><Source Token=\"1\" /></Starts></Rule><Rule RuleId=\"68013\" RuleVersion=\"9\" DataClassifications=\"SM\" Tar" ascii
    $s13 = "ex=\"1\" Nullable=\"false\"><Source Token=\"1\" Field=\"PayloadSize\" /></Column><Column OutType=\"UINT64\" Index=\"2\" Nullable" ascii
    $s14 = "/Column><Triggers><Source Token=\"1\" /></Triggers></Rule><Rule RuleId=\"90303\" RuleVersion=\"1\" DataClassifications=\"SM\" Ta" ascii
    $s15 = "riggers></Rule><Rule RuleId=\"68031\" RuleVersion=\"0\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"><Sources><ULSTag" ascii
    $s16 = "Type=\"WSTRING\" Index=\"2\" Nullable=\"true\"><Source Token=\"1\" Field=\"commandClickedEvents\" /></Column><Column OutType=\"U" ascii
    $s17 = "n=\"8\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"><Sources><ULSTagSource Token=\"1\" StringTagId=\"aw6ke\" /></Sou" ascii
    $s18 = "stant Value=\"TellMeD_CommandClickedEvents\" OutType=\"WSTRING\" /></Column><Triggers><Source Token=\"1\" /></Triggers></Rule><R" ascii
    $s19 = "</Triggers></Rule><Rule RuleId=\"68015\" RuleVersion=\"1\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"><Sources><ULS" ascii
    $s20 = "1\" /></Triggers></Rule><Rule RuleId=\"69600\" RuleVersion=\"1\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"><Source" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (8 of them)
    ) or (all of them)
}