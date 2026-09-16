import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_37 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "5847c0d50553d832c289b21658cf64bdae66267b2ef73b3751231791c076e525"
    hash3       = "94143e3c5b8bf576088fbdd4f8e39dabb3fa3deb0d3e54c9f019a0c50027f333"
    hash4       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
    hash5       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"
    hash6       = "cf617c50ba14391b1d4304d2d89eae47be73b674a501f2f2651cd50e46e58325"
    hash7       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $s1  = "=\"1\" F=\"0\" /></A></C><C T=\"FT\" I=\"1\" O=\"false\"><A T=\"MAX\"><S T=\"1\" F=\"0\" /></A></C><C T=\"W\" I=\"2\" O=\"false" ascii
    $s2  = "false\"><O T=\"COALESCE\"><L><S T=\"1\" F=\"TypeOfAttempt\" /></L><R><S T=\"2\" F=\"TypeOfAttempt\" /></R></O></C><C T=\"U32\" I" ascii
    $s3  = "UCSS T=\"20\" C=\"Identity SharedCred Client\" S=\"Monitorable\" /><UCSS T=\"21\" C=\"IdentityShipAssert\" S=\"Monitorable\" /><" ascii
    $s4  = " N=\"FailedToCreateBindUrl\"><O T=\"GE\"><L><C><S T=\"5\" /></C></L><R><V V=\"1\" T=\"U32\" /></R></O></C><C T=\"B\" I=\"5\" O=" ascii
    $s5  = "lse\" N=\"UserActionName\"><V V=\"TellMeD_SubstateServiceResponse\" T=\"W\" /></C><C T=\"W\" I=\"8\" O=\"true\" N=\"TraceId\"><S" ascii
    $s6  = "onCredStore\" S=\"Monitorable\" /><UCSS T=\"8\" C=\"Identity Authentication CredSync\" S=\"Monitorable\" /><UCSS T=\"9\" C=\"Ide" ascii
    $s7  = "edAccountCritical\" S=\"Monitorable\" /><UCSS T=\"12\" C=\"Identity Credentials Client\" S=\"Monitorable\" /><UCSS T=\"13\" C=\"" ascii
    $s8  = "110008\" /><F T=\"4\"><O T=\"EQ\"><L><S T=\"3\" F=\"0\" /></L><R><V V=\"CoAuth-ServerDoc\" T=\"W\" /></R></O></F></S><C T=\"U64" ascii
    $s9  = "S T=\"1\" F=\"TimeStamp100ns\" /></C><C T=\"G\" I=\"1\" O=\"false\" N=\"InteractionId\"><S T=\"1\" F=\"sessionId\" /></C><C T=\"" ascii
    $s10 = "0\" I=\"10min\"><S T=\"1\" /></TO></S><C T=\"I32\" I=\"0\" O=\"false\" N=\"AuthScheme\"><S T=\"1\" F=\"AuthScheme\" /></C><C T=" ascii
    $s11 = "\"><L><S T=\"1\" F=\"ErrorCode\" /></L><R><V V=\"2024\" T=\"U32\" /></R></O></R></O></R></O></F></S><G><S T=\"4\"><F N=\"DocId\"" ascii
    $s12 = "=\"fSaveAs\" /></C><C T=\"B\" I=\"9\" O=\"false\" N=\"OnBackgroundThread\"><S T=\"2\" F=\"fOnBackgroundThread\" /></C><C T=\"G\"" ascii
    $s13 = "=\"2\" O=\"falseNoError\" N=\"PeakEventCount\"><A T=\"MAX\"><S T=\"1\" F=\"EventCount\" /></A></C><C T=\"U32\" I=\"3\" O=\"false" ascii
    $s14 = "viceMapping\" S=\"Monitorable\" /><UCSS T=\"16\" C=\"Identity Exception\" S=\"Monitorable\" /><UCSS T=\"17\" C=\"Identity Http C" ascii
    $s15 = "alseNoError\" N=\"PromptStartTime\"><S T=\"1\" F=\"TimeStamp100ns\" /></C><C T=\"FT\" I=\"12\" O=\"true\" N=\"PromptEndTime\"><S" ascii
    $s16 = "C=\"Identity SignIn\" S=\"Monitorable\" /><UCSS T=\"23\" C=\"Identity OAuth2\" S=\"Monitorable\" /><UCSS T=\"24\" C=\"Identity T" ascii
    $s17 = "1\"><F N=\"sessionId\" /></S><S T=\"2\"><F N=\"sessionId\" /></S><S T=\"5\"><F N=\"0\" /></S><S T=\"6\"><F N=\"0\" /></S><S T=\"" ascii
    $s18 = "></R><R Id=\"63038\" V=\"1\" DC=\"SM\" T=\"Subrule\" xmlns=\"\"><S><UCSS T=\"1\" C=\"Identity OAuth2\" S=\"Unexpected Monitorabl" ascii
    $s19 = "></C><C T=\"G\" I=\"19\" O=\"true\" N=\"PromptCorrelation\"><S T=\"1\" F=\"Prompt Correlation\" M=\"Ignore\" /></C><T><S T=\"10" ascii
    $s20 = "nitorable\" /><UCSS T=\"18\" C=\"Identity LiveOAuth Client\" S=\"Monitorable\" /><UCSS T=\"19\" C=\"IdentityPublicApi\" S=\"Moni" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (8 of them)
    ) or (all of them)
}