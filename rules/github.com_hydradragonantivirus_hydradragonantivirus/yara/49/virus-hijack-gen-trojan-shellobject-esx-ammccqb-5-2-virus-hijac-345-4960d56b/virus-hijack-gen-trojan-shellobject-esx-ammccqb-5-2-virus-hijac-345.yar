import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_345 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
    hash3       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"
    hash4       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $s1 = "><C T=\"W\" I=\"0\" O=\"false\" N=\"EventName\"><S T=\"2\" F=\"EventName\" /></C><C T=\"W\" I=\"1\" O=\"true\" N=\"EventContract" ascii
    $s2 = "T=\"W\" I=\"4\" O=\"false\" N=\"EventData\"><S T=\"2\" F=\"EventData\" /></C><C T=\"W\" I=\"5\" O=\"false\" N=\"EventContractInf" ascii
    $s3 = "ract\" M=\"Ignore\" /></C><C T=\"U64\" I=\"2\" O=\"false\" N=\"EventFlags\"><S T=\"2\" F=\"EventFlags\" /></C><C T=\"D\" I=\"3\"" ascii
    $s4 = "ContractInfo\" /></C><C T=\"W\" I=\"6\" O=\"false\" N=\"EventTypeInfo\"><S T=\"2\" F=\"EventTypeInfo\" /></C><C T=\"W\" I=\"7\" " ascii
    $s5 = "=\"W\" I=\"4\" O=\"false\" N=\"EventData\"><S T=\"2\" F=\"EventData\" /></C><C T=\"W\" I=\"5\" O=\"false\" N=\"EventContractInfo" ascii
    $s6 = "te\"><V V=\"1.0\" T=\"D\" /></C><C T=\"W\" I=\"4\" O=\"false\" N=\"EventData\"><S T=\"2\" F=\"EventData\" /></C><C T=\"W\" I=\"5" ascii
    $s7 = "1\" F=\"EventSamplingPolicy\" /></L><R><V V=\"191\" T=\"U8\" /></R></O></F></S><C T=\"W\" I=\"0\" O=\"false\" N=\"EventName\"><S" ascii
    $s8 = "se\" N=\"EventTypeInfo\"><S T=\"2\" F=\"EventTypeInfo\" /></C><C T=\"W\" I=\"7\" O=\"false\" N=\"EventDataClassificationInfo\"><" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (all of them)
    ) or (all of them)
}