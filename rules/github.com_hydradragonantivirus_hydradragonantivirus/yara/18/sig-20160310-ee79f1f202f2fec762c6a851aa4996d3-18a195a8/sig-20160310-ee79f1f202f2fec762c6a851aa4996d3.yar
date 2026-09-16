rule sig_20160310_ee79f1f202f2fec762c6a851aa4996d3 {
  meta:
    description = "datamaliciousorder - file 20160310_ee79f1f202f2fec762c6a851aa4996d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fe0bcd22f0ef7174c2c648840f808f073c332b28716a223b1384cea0218a2fc"

  strings:
    $s1  = "var od = true  , fmQq = OsG[7] + OsG[9] + OsG[11];" fullword ascii
    $s2  = "return SBSQrxd[0] + SBSQrxd[2] + SBSQrxd[4] + \".F\" + SBSQrxd[7] + SBSQrxd[9] + SBSQrxd[12] + SBSQrxd[14];" fullword ascii
    $s3  = "var SBSQrxd = \"Sc NqZbPiO r bTrlrqWlt ipting dpKPhKs Hfi ile RrxenWKFegPZmo System TZ UbTLy Obj KXEljG ect nqqYSAJ\".split(\" " ascii
    $s4  = "vsfwg.open(sqPlj,mlQkX,false);" fullword ascii
    $s5  = "var OsG = (\"2.XMLHTTP yMNFHmB jMNoH XML ream St uiHJqkpj AD rBeqEug O ezGY D\").split(\" \");" fullword ascii
    $s6  = "function CbrkRbXA() {" fullword ascii
    $s7  = "BhoY(WAa); WAa.type = 1; IRvd(WAa,BVUtPWN(pa)); if (kHfP(ZlfDEkcg(WAa)))  {" fullword ascii
    $s8  = "function IRvd(yWDcF,smwmt) {" fullword ascii
    $s9  = "function kHfP(RkxJL) {" fullword ascii
    $s10 = "return OnXJn.status;" fullword ascii
    $s11 = "function Ngsx(OnXJn) {" fullword ascii
    $s12 = "function ZxsGZ(wPrelN) {" fullword ascii
    $s13 = "function RidG(MPGol) {" fullword ascii
    $s14 = "function BhoY(aLQaV) {" fullword ascii
    $s15 = "return Ycvr.ExpandEnvironmentStrings(LrdMD);" fullword ascii
    $s16 = "function kmQWGZroa(anUgKWxiXqF) {" fullword ascii
    $s17 = "function gEND(KFlmX) {" fullword ascii
    $s18 = "return HvG.size;" fullword ascii
    $s19 = "function mYONV(WAZerS) {" fullword ascii
    $s20 = "function OwsPSbsu(phFNx,XZoIMs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}