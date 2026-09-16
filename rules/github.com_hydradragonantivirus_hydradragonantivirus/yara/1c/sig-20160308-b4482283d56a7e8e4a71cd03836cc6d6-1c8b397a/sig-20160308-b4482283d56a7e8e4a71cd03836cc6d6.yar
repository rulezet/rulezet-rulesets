rule sig_20160308_b4482283d56a7e8e4a71cd03836cc6d6 {
  meta:
    description = "datamaliciousorder - file 20160308_b4482283d56a7e8e4a71cd03836cc6d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ddc89cd260b6fe09ea4e963ccdc878272b5ab3b819b3ad7c87ef28495a38b5b"

  strings:
    $s1  = "var Yb = true  , SuRl = JyG[7] + JyG[9] + JyG[11];" fullword ascii
    $s2  = "return yNhiqFU[0] + yNhiqFU[2] + yNhiqFU[4] + \".F\" + yNhiqFU[7] + yNhiqFU[9] + yNhiqFU[12] + yNhiqFU[14];" fullword ascii
    $s3  = "zICYd.open(SAyzq,rlNBz,false);" fullword ascii
    $s4  = "var JyG = (\"2.XMLHTTP TgZLAXQ rQjar XML ream St QSpewuVC AD rDMVEBP O EFlq D\").split(\" \");" fullword ascii
    $s5  = "function TAWW(EAjtQ) {" fullword ascii
    $s6  = "function fSaqDAuAS(AMafovjwrXN) {" fullword ascii
    $s7  = "Hne = X; break; " fullword ascii
    $s8  = "function CLGQ(CHDte) {" fullword ascii
    $s9  = "return new ActiveXObject(IfvNWC);" fullword ascii
    $s10 = "return uTW.size;" fullword ascii
    $s11 = "function oIOShWuIO(FvkBV,REbxY,wBTjb,reEa) {" fullword ascii
    $s12 = "function NrKqFVHR(uTW) {" fullword ascii
    $s13 = "function zoNmT(IfvNWC) {" fullword ascii
    $s14 = "function ptNh(xlfLf) {" fullword ascii
    $s15 = "function pLnZlvUs() {" fullword ascii
    $s16 = "if(X>=F.length) {break;}" fullword ascii
    $s17 = "return yFFV.responseBody;" fullword ascii
    $s18 = "function uJXw(EmRDS) {" fullword ascii
    $s19 = "return TnsHw.status;" fullword ascii
    $s20 = "if (CHDte > 152700-282){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}