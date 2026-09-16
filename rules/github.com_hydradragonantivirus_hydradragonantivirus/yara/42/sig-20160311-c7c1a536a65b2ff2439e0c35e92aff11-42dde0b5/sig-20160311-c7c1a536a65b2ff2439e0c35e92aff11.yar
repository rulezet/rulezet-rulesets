rule sig_20160311_c7c1a536a65b2ff2439e0c35e92aff11 {
  meta:
    description = "datamaliciousorder - file 20160311_c7c1a536a65b2ff2439e0c35e92aff11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae58a3faa463791114e2df165632c4c453aed21db478c6b391aea0ba7325a8d1"

  strings:
    $s1  = "var FT = true  , lVzY = VBD[7] + VBD[9] + VBD[11];" fullword ascii
    $s2  = "return xklRTEq[0] + xklRTEq[2] + xklRTEq[4] + \".F\" + xklRTEq[7] + xklRTEq[9] + xklRTEq[12] + xklRTEq[14];" fullword ascii
    $s3  = "var xklRTEq = \"Sc umEKVcx r mpXAamgTw ipting QFlFLjl Xih ile AGTjXwyKaBIWCy System PR XtYDn Obj ymjOEp ect BWsdVdq\".split(\" " ascii
    $s4  = "WYxPr.open(VISUK,QjFpo,false);" fullword ascii
    $s5  = "var VBD = (\"2.XMLHTTP kntvUms nkELD XML ream St RnRHLYmD AD lEsyjgK O Fepv D\").split(\" \");" fullword ascii
    $s6  = "function ICyiGNfw(XDLfn,bizEwH) {" fullword ascii
    $s7  = "function cCqc(qPdTo) {" fullword ascii
    $s8  = "KSL = M; break; " fullword ascii
    $s9  = "function BcFx(WYxPr,QjFpo,VISUK) {" fullword ascii
    $s10 = "if(M>=m.length) {break;}" fullword ascii
    $s11 = "function ClgX(nihfl) {" fullword ascii
    $s12 = "return new ActiveXObject(mpNBoQ);" fullword ascii
    $s13 = "return GIpo.responseBody;" fullword ascii
    $s14 = "return ubHPWHt(Ou,CTkdk[725-719]+CTkdk[295-288]+CTkdk[461-453]);" fullword ascii
    $s15 = "return zrSMq;" fullword ascii
    $s16 = "function uqits(mpNBoQ) {" fullword ascii
    $s17 = "return GvOOoyF" fullword ascii
    $s18 = "function CqIoR(qiXjrn) {" fullword ascii
    $s19 = "function ubHPWHt(NSmX,RZmDj) {" fullword ascii
    $s20 = "function lpYBYjIfC() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}