rule sig_20160310_88fba3b1594598bf690ed7ebb98d2ff6 {
  meta:
    description = "datamaliciousorder - file 20160310_88fba3b1594598bf690ed7ebb98d2ff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34787eaa0d17ce413603dfce347d83c1e3550b63d9de33f1546eebdc299dd31e"

  strings:
    $s1  = "return AjEHFog[0] + AjEHFog[2] + AjEHFog[4] + \".F\" + AjEHFog[7] + AjEHFog[9] + AjEHFog[12] + AjEHFog[14];" fullword ascii
    $s2  = "var Ig = true  , epzy = Hdm[7] + Hdm[9] + Hdm[11];" fullword ascii
    $s3  = "dGWwA.open(KXrSB,JHvFc,false);" fullword ascii
    $s4  = "function pdbcT(DeXdeS) {" fullword ascii
    $s5  = "return YvdS.responseBody;" fullword ascii
    $s6  = "function wuEC(dGWwA,JHvFc,KXrSB) {" fullword ascii
    $s7  = "return JvNTt.status;" fullword ascii
    $s8  = "return DeXdeS.position=872-872;" fullword ascii
    $s9  = "function MQaKwHfM(lZwuK,HutlhV) {" fullword ascii
    $s10 = "function WNuHtvOf(Ysj) {" fullword ascii
    $s11 = "return new ActiveXObject(CphaUx);" fullword ascii
    $s12 = "function WYjwOPpHj(aPcPJ,icPPv,jolRb,yiyl) {" fullword ascii
    $s13 = "function pPFR(QCBiY,Aijyl) {" fullword ascii
    $s14 = "function TUba(JoBjU) {" fullword ascii
    $s15 = "return BEFux;" fullword ascii
    $s16 = "return ZvhJOZK" fullword ascii
    $s17 = "function GRDJ(oOTXy,Dkrjw) {" fullword ascii
    $s18 = "function dfmm(erCKG) {" fullword ascii
    $s19 = "function SOaglLS(YvdS) {" fullword ascii
    $s20 = "if (oqTVZ > 177187-897){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}