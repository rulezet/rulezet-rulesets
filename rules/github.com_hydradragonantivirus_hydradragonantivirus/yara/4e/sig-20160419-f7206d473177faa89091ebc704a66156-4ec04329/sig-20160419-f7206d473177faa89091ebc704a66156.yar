rule sig_20160419_f7206d473177faa89091ebc704a66156 {
  meta:
    description = "datamaliciousorder - file 20160419_f7206d473177faa89091ebc704a66156.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02c10ba6f78f511a8059cf47d964b8cebce4ccb25e928c5101426a9a15cd2424"

  strings:
    $s1  = "var aW = true  , PKWJ = oqq[7] + oqq[9] + oqq[11];" fullword ascii
    $s2  = "return MekwJNx[0] + MekwJNx[2] + MekwJNx[4] + \".F\" + MekwJNx[7] + MekwJNx[9] + MekwJNx[12] + MekwJNx[14];" fullword ascii
    $s3  = "var oqq = (\"2.XMLHTTP PvnSJOW UTqyv XML ream St DYYxKgjT AD gnUWCwr O uSZx D\").split(\" \");" fullword ascii
    $s4  = "LFUv.open(iVbtD,SINSe,false);" fullword ascii
    $s5  = "if (V >= IcHmI.length) {break;}" fullword ascii
    $s6  = "function dSqBlqL(nGxU,igBfF) {" fullword ascii
    $s7  = "ZEv = Q; break; " fullword ascii
    $s8  = "return YHfF[vDjfzMT[0]+vDjfzMT[1]];" fullword ascii
    $s9  = "function gOZjPUIh(gfE) {" fullword ascii
    $s10 = "function FYFp(IcHmI) {" fullword ascii
    $s11 = "return RovAuSJ[0];" fullword ascii
    $s12 = "function ugLfv(FNx,vhxHL) {" fullword ascii
    $s13 = "JKLu(htE); htE.type = 1; Kath(htE,HALcuBN(HK)); if (TRdq(gOZjPUIh(htE)))  {" fullword ascii
    $s14 = "function NyUO(CSaVB,SINSe,iVbtD) {" fullword ascii
    $s15 = "function VOwrz(AvcXOh) {" fullword ascii
    $s16 = "function BftfYD(CVmn,nMvRmz) {" fullword ascii
    $s17 = "function RePH(szFnu,jeDkw) {" fullword ascii
    $s18 = "return phCDqF[EozZ[201-201]]=157-157;" fullword ascii
    $s19 = "function zjDF(GJtNH) {" fullword ascii
    $s20 = "function HALcuBN(YHfF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}