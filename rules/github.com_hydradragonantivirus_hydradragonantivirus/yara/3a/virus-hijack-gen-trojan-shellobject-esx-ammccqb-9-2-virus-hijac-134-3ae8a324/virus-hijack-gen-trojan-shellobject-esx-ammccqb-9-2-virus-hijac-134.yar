import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_9_2_Virus_Hijac_134 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94143e3c5b8bf576088fbdd4f8e39dabb3fa3deb0d3e54c9f019a0c50027f333"
    hash2       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $x1  = "!!!!!fuk-tcpa!!!!!<?xml version=\"1.0\" encoding=\"utf-8\"?><Rules xmlns=\"urn:Rules\"><Rule RuleId=\"1000\" RuleVersion=\"5\" D" ascii
    $s2  = "ken=\"1\" Field=\"ComputerSystemProductId\" MissingFieldHandling=\"Ignore\" /></UnaryOperator></Column><Triggers><Source Token=" ascii
    $s3  = "fications=\"ESM\" Target=\"Upload-Medium\" xmlns=\"\"><Sources><RuleSource Token=\"1\" RuleId=\"120114\" /><Filter Token=\"2\"><" ascii
    $s4  = "r Type=\"EQ\"><Left><Source Token=\"1\" Field=\"ErrorCode\" /></Left><Right><Constant Value=\"2027\" OutType=\"UINT32\" /></Righ" ascii
    $s5  = "=\"SM\" Target=\"Upload\" xmlns=\"\"><Sources><ULSTagSource Token=\"1\" StringTagId=\"a70rj\" /></Sources><Column OutType=\"UINT" ascii
    $s6  = "e=\"true\"><Source Token=\"3\" Field=\"ProcessorFrequency\" MissingFieldHandling=\"Ignore\" /></Column><Column OutType=\"BOOL\" " ascii
    $s7  = "mn OutType=\"WSTRING\" Index=\"13\" Nullable=\"false\"><Source Token=\"3\" Field=\"ProcessorArchitecture\" /></Column><Column Ou" ascii
    $s8  = "ule><Rule RuleId=\"110164\" RuleVersion=\"0\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"><Sources><RuleSource Token" ascii
    $s9  = "leId=\"120102\" RuleVersion=\"10\" DataClassifications=\"SM\" Target=\"Upload-Medium\" xmlns=\"\"><Sources><StateSource Token=\"" ascii
    $s10 = "Sources><Column OutType=\"WSTRING\" Index=\"0\" Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessorArchitecture\" MissingFie" ascii
    $s11 = "><Triggers><Source Token=\"2\" /></Triggers></Rule><Rule RuleId=\"120103\" RuleVersion=\"11\" DataClassifications=\"SM\" Target=" ascii
    $s12 = "T32\" Index=\"14\" Nullable=\"false\"><Source Token=\"3\" Field=\"ProcessorCount\" /></Column><Column OutType=\"UINT32\" Index=" ascii
    $s13 = "></Rule><Rule RuleId=\"120108\" RuleVersion=\"5\" DataClassifications=\"ESM\" Target=\"Upload\" xmlns=\"\"><Sources><RuleSource " ascii
    $s14 = "=\"Ignore\" /></Column><Column OutType=\"UINT32\" Index=\"1\" Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessorCount\" Mis" ascii
    $s15 = "dling=\"Ignore\" /></Column><Column OutType=\"WSTRING\" Index=\"15\" Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessFileNa" ascii
    $s16 = "ce Token=\"3\" /></Starts></Rule><Rule RuleId=\"120113\" RuleVersion=\"6\" DataClassifications=\"SM ESM\" Target=\"Upload-Medium" ascii
    $s17 = "ProcessSessionId\" /></Column><Column OutType=\"INT32\" Index=\"3\" Nullable=\"false\"><Source Token=\"1\" Field=\"CrashType\" /" ascii
    $s18 = "n=\"2\" /><Source Token=\"3\" /></Triggers></Rule><Rule RuleId=\"120125\" RuleVersion=\"0\" DataClassifications=\"SM\" Target=\"" ascii
    $s19 = "n><Column OutType=\"WSTRING\" Index=\"9\" Nullable=\"false\"><Source Token=\"2\" Field=\"ProcessFileName\" /></Column><Column Ou" ascii
    $s20 = "><Left><Source Token=\"1\" Field=\"Event\" /></Left><Right><Constant Value=\"4\" OutType=\"UINT8\" /></Right></Operator></Right>" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}