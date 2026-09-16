rule sig_20160310_90ed703c21db87f67ae89a78c12219ac {
  meta:
    description = "datamaliciousorder - file 20160310_90ed703c21db87f67ae89a78c12219ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1dac9e51892b6954470fc0954510d914c98ea14e64b47838960f13753af8070"

  strings:
    $s1  = "return AdkXVak[0] + AdkXVak[2] + AdkXVak[4] + \".F\" + AdkXVak[7] + AdkXVak[9] + AdkXVak[12] + AdkXVak[14];" fullword ascii
    $s2  = "var pS = true  , XbpK = kBH[7] + kBH[9] + kBH[11];" fullword ascii
    $s3  = "var kBH = (\"2.XMLHTTP WCUeZdj hzUvH XML ream St iUbZojyq AD mUIXqMN O Jami D\").split(\" \");" fullword ascii
    $s4  = "var AdkXVak = \"Sc wMRGrUY r tkuNstEHy ipting sauLvmH yqn ile hoAGYJjRbPEaGF System et KtpCF Obj NKkBcg ect kglLBSg\".split(\" " ascii
    $s5  = "bUzEZ.open(mrdqr,DDAVg,false);" fullword ascii
    $s6  = "function GeSi(CwnkG) {" fullword ascii
    $s7  = "function udwi(ZLPBQ,MkWEX) {" fullword ascii
    $s8  = "function SKnrdHZK(VaRTu,FYsfJr) {" fullword ascii
    $s9  = "function rTOA(GJSpM,HgRkl) {" fullword ascii
    $s10 = "function BeCt(bUzEZ,DDAVg,mrdqr) {" fullword ascii
    $s11 = "if (e >= ltHfM.length) {break;}" fullword ascii
    $s12 = "if(Q>=O.length) {break;}" fullword ascii
    $s13 = "return ZjdkrU.position=142-142;" fullword ascii
    $s14 = "function zPBYqjJbB(udLRp,OxHuK,YMxHP,wAHL) {" fullword ascii
    $s15 = "return CwnkG.status;" fullword ascii
    $s16 = "if (SWThl > 192801-666){return true;} else {return false;}" fullword ascii
    $s17 = "return MVGTd;" fullword ascii
    $s18 = "function yIfFG(BTEIKJ) {" fullword ascii
    $s19 = "function JiAR(hJkkm) {" fullword ascii
    $s20 = "return vMkKAaT(yo,JFIAd[106-100]+JFIAd[769-762]+JFIAd[260-252]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}