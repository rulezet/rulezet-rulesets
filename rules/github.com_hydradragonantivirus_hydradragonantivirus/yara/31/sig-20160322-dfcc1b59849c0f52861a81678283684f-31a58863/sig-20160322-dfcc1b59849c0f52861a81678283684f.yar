rule sig_20160322_dfcc1b59849c0f52861a81678283684f {
  meta:
    description = "datamaliciousorder - file 20160322_dfcc1b59849c0f52861a81678283684f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "245d15edeaadcce8a2c3ea2957c9cb8326c86e45e7708aae02442913e9ba4df4"

  strings:
    $s1  = "return WScript.CreateObject(WJviL);" fullword ascii
    $s2  = "var Ly = true  , okeJ = uUS[7] + uUS[9] + uUS[11];" fullword ascii
    $s3  = "return YJNUYbb[0] + YJNUYbb[2] + YJNUYbb[4] + \".F\" + YJNUYbb[7] + YJNUYbb[9] + YJNUYbb[12] + YJNUYbb[14];" fullword ascii
    $s4  = "var uUS = (\"2.XMLHTTP GLcGleB yVUfr XML ream St IsMqPHCl AD RxJPpLQ O OsMp D\").split(\" \");" fullword ascii
    $s5  = "var YJNUYbb = GMeJE(WYXYMwizKE+\" \"+\"System Ps oOQAp Obj ezOwlf ect KzkXpkR VXPGC\", \" \");" fullword ascii
    $s6  = "lTkv.open(cltyg,OllLI,false);" fullword ascii
    $s7  = "if(D>=W.length) {break;}" fullword ascii
    $s8  = "function JqBN(lPsGa,zovvR) {" fullword ascii
    $s9  = "return BWT.split(BHESx);" fullword ascii
    $s10 = "if (l >= XkLdM.length) {break;}" fullword ascii
    $s11 = "return FndeIvk(bl,VPUWu[565-559]+VPUWu[336-329]+VPUWu[586-578]);" fullword ascii
    $s12 = "return dWAQ[VGKzyy[0]];" fullword ascii
    $s13 = "Pyb = D; break; " fullword ascii
    $s14 = "function emCPLdVF(SyMj) {" fullword ascii
    $s15 = "function kqBm(WJviL) {" fullword ascii
    $s16 = "return new ActiveXObject(AxojVA);" fullword ascii
    $s17 = "return OEapZ.status;" fullword ascii
    $s18 = "function iUFgY(AxojVA) {" fullword ascii
    $s19 = "function bqQLUWbYb(HXPJdclzDpN) {" fullword ascii
    $s20 = "function dAjy(XkLdM) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}