rule sig_20160321_b4335f9ca2801ef2169117d0b8e6d519 {
  meta:
    description = "datamaliciousorder - file 20160321_b4335f9ca2801ef2169117d0b8e6d519.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b19782671464ab3503a1053a4a3b86d06e3c212339c7e9fe642e2bfc44fd0dd"

  strings:
    $s1  = "return WScript.CreateObject(yXYIf);" fullword ascii
    $s2  = "var fx = true  , fMGs = vtn[7] + vtn[9] + vtn[11];" fullword ascii
    $s3  = "var vtn = (\"2.XMLHTTP OXEFWWl vEjtw XML ream St dRRHpmLF AD TQCPkRP O GArs D\").split(\" \");" fullword ascii
    $s4  = "kTVEW.open(qfboj,dHcMU,false);" fullword ascii
    $s5  = "var acABweL = jgIpl(lwtjBPIKdI+\" \"+\"System uL DUOlK Obj tmPysJ ect kMDUIkd xEdEE\", \" \");" fullword ascii
    $s6  = "if(x>=h.length) {break;}" fullword ascii
    $s7  = "if (AjzHm > 181538-839){return true;} else {return false;}" fullword ascii
    $s8  = "return Mtibg;" fullword ascii
    $s9  = "function dpll(Qdpal) {" fullword ascii
    $s10 = "function tZBR(qyimx) {" fullword ascii
    $s11 = "function jgIpl(dRj,OWNQA) {" fullword ascii
    $s12 = "function QTlx(PQGUA) {" fullword ascii
    $s13 = "function RKftbhPT(eVa) {" fullword ascii
    $s14 = "return mPsKRu.position=182-182;" fullword ascii
    $s15 = "function RFIHRpPe(hbnt) {" fullword ascii
    $s16 = "function BJUXO(ScrNzy) {" fullword ascii
    $s17 = "function kCHF(AjzHm) {" fullword ascii
    $s18 = "function bitfuFHmF(LncPSiherbU) {" fullword ascii
    $s19 = "return new ActiveXObject(ScrNzy);" fullword ascii
    $s20 = "return ZKkaIPC(iU,IZgwX[626-620]+IZgwX[752-745]+IZgwX[393-385]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}