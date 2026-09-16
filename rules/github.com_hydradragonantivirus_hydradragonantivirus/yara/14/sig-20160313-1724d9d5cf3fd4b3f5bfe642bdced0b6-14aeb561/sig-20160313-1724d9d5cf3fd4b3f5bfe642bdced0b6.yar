rule sig_20160313_1724d9d5cf3fd4b3f5bfe642bdced0b6 {
  meta:
    description = "datamaliciousorder - file 20160313_1724d9d5cf3fd4b3f5bfe642bdced0b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c90abf16a201dc9bdd6ad3c57fabaf5dba56c567852751d166ff719667bc550"

  strings:
    $s1  = "var HzH = JeRL(UKSg + \"B.\" + TSe[5]+(555767, TSe[4]));" fullword ascii
    $s2  = "var TRNZDIAl = JeRL(SxPGpebM[737-736] + SxPGpebM[925-922] + SxPGpebM[626-621] + SxPGpebM[826-820] + SxPGpebM[512-504] + SxPGpebM" ascii
    $s3  = "var TRNZDIAl = JeRL(SxPGpebM[737-736] + SxPGpebM[925-922] + SxPGpebM[626-621] + SxPGpebM[826-820] + SxPGpebM[512-504] + SxPGpebM" ascii
    $s4  = "return NGjzNvD[0] + NGjzNvD[2] + NGjzNvD[4] + \".F\" + NGjzNvD[7] + NGjzNvD[9] + NGjzNvD[12] + NGjzNvD[14];" fullword ascii
    $s5  = "var zY = true  , UKSg = TSe[7] + TSe[9] + TSe[11];" fullword ascii
    $s6  = "var NGjzNvD = \"Sc ItZrXON r CWkOKSjZD ipting oZiAesM bnx ile UJZHLHqQWPMiWv System Cl TBHHj Obj YQZEXK ect ROEIqXg\".split(\" " ascii
    $s7  = "var TSe = (\"2.XMLHTTP knTPVcv JaGKX XML ream St waQyIQYD AD lFXywYD O sqNl D\").split(\" \");" fullword ascii
    $s8  = "PwgDA.open(ezeEw,UsfiI,false);" fullword ascii
    $s9  = "function WVty(jDPDw) {" fullword ascii
    $s10 = "function iEGL(ynXbX,bPKtC) {" fullword ascii
    $s11 = "return aGldqPx" fullword ascii
    $s12 = "return KnGv.ExpandEnvironmentStrings(YmkNQ);" fullword ascii
    $s13 = "if(L>=u.length) {break;}" fullword ascii
    $s14 = "function HoAqavK(DItN) {" fullword ascii
    $s15 = "function oQXiCwSZ() {" fullword ascii
    $s16 = "function Llwjc(jUTDih) {" fullword ascii
    $s17 = "function ymkjNrL(KnGv,YmkNQ) {" fullword ascii
    $s18 = "return jUTDih.position=951-951;" fullword ascii
    $s19 = "return new ActiveXObject(eEdnuk);" fullword ascii
    $s20 = "var HD = JeRL(KOw);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}