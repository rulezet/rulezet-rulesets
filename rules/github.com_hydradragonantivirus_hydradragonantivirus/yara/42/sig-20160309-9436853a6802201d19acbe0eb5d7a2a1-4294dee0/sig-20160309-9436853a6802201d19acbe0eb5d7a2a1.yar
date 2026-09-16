rule sig_20160309_9436853a6802201d19acbe0eb5d7a2a1 {
  meta:
    description = "datamaliciousorder - file 20160309_9436853a6802201d19acbe0eb5d7a2a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d05cdbb26e50d819383bf7b5ff2358a9b0c2ec194d629044072e375efc47289c"

  strings:
    $s1  = "return XpaxDSu[0] + XpaxDSu[2] + XpaxDSu[4] + \".F\" + XpaxDSu[7] + XpaxDSu[9] + XpaxDSu[12] + XpaxDSu[14];" fullword ascii
    $s2  = "var dn = true  , Dteb = nyu[7] + nyu[9] + nyu[11];" fullword ascii
    $s3  = "var XpaxDSu = \"Sc mzQqNfg r aDSLuAvIL ipting yXhxbgY QoR ile UkCgFRFPEadhod System EK UyGSC Obj qnSIyP ect BFBaDvh\".split(\" " ascii
    $s4  = "kxkRB.open(hUYtl,jjAmA,false);" fullword ascii
    $s5  = "var nyu = (\"2.XMLHTTP qrbrUuk QwRBX XML ream St pTrGxguc AD HcZKtng O QdhD D\").split(\" \");" fullword ascii
    $s6  = "function EgjsAHcb(XTT) {" fullword ascii
    $s7  = "function uSGx(bBLyy) {" fullword ascii
    $s8  = "return oace.responseBody;" fullword ascii
    $s9  = "IKE = D; break; " fullword ascii
    $s10 = "function FXVF(uspmM,KDalo) {" fullword ascii
    $s11 = "if (enMDX == 599-399){return true;} else {return false;}" fullword ascii
    $s12 = "function RGKIotB(rETu,RuaMZ) {" fullword ascii
    $s13 = "return REpNF.status;" fullword ascii
    $s14 = "return ImyLdys" fullword ascii
    $s15 = "function lOeu(UItaK,JotAe) {" fullword ascii
    $s16 = "function Phfk(IGQZx) {" fullword ascii
    $s17 = "function oSFQlYtq(mllYm,AyKJdz) {" fullword ascii
    $s18 = "if (T >= HMdWz.length) {break;}" fullword ascii
    $s19 = "if (Cpjea > 200695-843){return true;} else {return false;}" fullword ascii
    $s20 = "return XTT.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}