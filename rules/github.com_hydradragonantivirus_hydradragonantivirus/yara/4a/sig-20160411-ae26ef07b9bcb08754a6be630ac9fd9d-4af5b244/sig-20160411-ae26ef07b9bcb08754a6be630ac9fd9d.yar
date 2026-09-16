rule sig_20160411_ae26ef07b9bcb08754a6be630ac9fd9d {
  meta:
    description = "datamaliciousorder - file 20160411_ae26ef07b9bcb08754a6be630ac9fd9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d159962ce7d99db556b3abb44522be70ae063c100e5fb90c2d6c190ee030978a"

  strings:
    $s1  = "return RwcghEx[0] + RwcghEx[2] + RwcghEx[4] + \".F\" + RwcghEx[7] + RwcghEx[9] + RwcghEx[12] + RwcghEx[14];" fullword ascii
    $s2  = "var cB = true  , gFPC = YJV[7] + YJV[9] + YJV[11];" fullword ascii
    $s3  = "CCyz.open(EinlV,qBcRI,false);" fullword ascii
    $s4  = "var YJV = (\"2.XMLHTTP vgaSMMr CkYrx XML ream St dTqCfFjP AD TAzaajj O UqIv D\").split(\" \");" fullword ascii
    $s5  = "function CTwLY(uyobdZ) {" fullword ascii
    $s6  = "function CTLO(jyOaw) {" fullword ascii
    $s7  = "return hTFX[hVcQqQu[0]+hVcQqQu[1]];" fullword ascii
    $s8  = "function aUARaAHJT(kncjTmcToWh) {" fullword ascii
    $s9  = "return \"qXHhcUUlTSoORe\";" fullword ascii
    $s10 = "function ZwuAea(styaTDV) {" fullword ascii
    $s11 = "function YRsBP(YmJgvfzp,ALPX) {" fullword ascii
    $s12 = "function LiVw(iPWsr) {" fullword ascii
    $s13 = "function QLLdY(iiP,ATaSU) {" fullword ascii
    $s14 = "return iiP[PHdv[0]](ATaSU);" fullword ascii
    $s15 = "function GbBV(nblRH) {" fullword ascii
    $s16 = "if(B>=I.length) {break;}" fullword ascii
    $s17 = "function uhancy(mTkR,OSUAqm) {" fullword ascii
    $s18 = "function ZrxjMwE(hTFX) {" fullword ascii
    $s19 = "return osGLRjK;" fullword ascii
    $s20 = "function iccu(mazRn,zogJL) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}