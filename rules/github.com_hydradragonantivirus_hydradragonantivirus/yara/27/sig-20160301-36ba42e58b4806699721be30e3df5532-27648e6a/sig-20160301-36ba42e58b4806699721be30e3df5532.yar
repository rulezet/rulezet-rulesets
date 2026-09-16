rule sig_20160301_36ba42e58b4806699721be30e3df5532 {
  meta:
    description = "datamaliciousorder - file 20160301_36ba42e58b4806699721be30e3df5532.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d83a5c23460e2c6e31b34021c89411fe5650a3226f1fde3bd1a55cfee8bf7c"

  strings:
    $s1  = "var nQ = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "function OkLq(dOORF) {" fullword ascii
    $s3  = "var JVz = (JCE + \"TTP\" + \" nvJwcEl NMZbM XML ream St lncBHJCe AD gpODsna OD\").split(\" \");" fullword ascii
    $s4  = "var TU = true  , PNyi = JVz[7] + \"\" + JVz[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + fvzqnGS + \".F\" + ZGMjqCgrjS + awDYP + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "gZWyp.open(sNgSX,mxVZQ,false);" fullword ascii
    $s7  = "return WScript.CreateObject(ggcAU);" fullword ascii
    $s8  = "function DSRX(ZnsSa,ScbGM) {" fullword ascii
    $s9  = "function otCrxWzUL(RmFMY,Wcxwm,VPoDO) {" fullword ascii
    $s10 = "function MKUq(CGWlR) {" fullword ascii
    $s11 = "function ISIy(NloSS) {" fullword ascii
    $s12 = "function rKfbCuiC() {" fullword ascii
    $s13 = "function pjLZ(Qqcix) {" fullword ascii
    $s14 = "return ouqHU;" fullword ascii
    $s15 = "function wfbl(ZNuCK) {" fullword ascii
    $s16 = "return ISDqH.status;" fullword ascii
    $s17 = "if(E>=O.length) {break;}" fullword ascii
    $s18 = "return new ActiveXObject(EbSxmf);" fullword ascii
    $s19 = "function MdJY(gZWyp,mxVZQ,sNgSX) {" fullword ascii
    $s20 = "function LiOOc(EbSxmf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}