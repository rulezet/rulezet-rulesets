rule sig_20160311_fe56a3d68f66a44b2ac49658826ab531 {
  meta:
    description = "datamaliciousorder - file 20160311_fe56a3d68f66a44b2ac49658826ab531.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82e07f76be737760e5bdbde48cd74632cf9b34ed233bed7a13b988ada66fc10b"

  strings:
    $s1  = "return GeTVtw.position=789-789;" fullword ascii
    $s2  = "function PLUBz(GeTVtw) {" fullword ascii
    $s3  = "var PO = true  , rybI = Vtk[7] + Vtk[9] + Vtk[11];" fullword ascii
    $s4  = "return eIUvqiv[0] + eIUvqiv[2] + eIUvqiv[4] + \".F\" + eIUvqiv[7] + eIUvqiv[9] + eIUvqiv[12] + eIUvqiv[14];" fullword ascii
    $s5  = "var Vtk = (\"2.XMLHTTP UxqcIIN BKBTW XML ream St jzdFBMKQ AD LbYqnwA O SqrU D\").split(\" \");" fullword ascii
    $s6  = "UWJWK.open(rGHwu,moQWa,false);" fullword ascii
    $s7  = "var eIUvqiv = \"Sc VWKtBBr r zUaKUOgur ipting TYsbKJF fRy ile sawyDeapwlpczK System XE WoxOX Obj wBFAUA ect QGyicgl\".split(\" " ascii
    $s8  = "function PHsF(QgMad) {" fullword ascii
    $s9  = "function AIExbplly() {" fullword ascii
    $s10 = "function CVGb(NzOox) {" fullword ascii
    $s11 = "if (m >= VcPjs.length) {break;}" fullword ascii
    $s12 = "function ykTB(xSYVg) {" fullword ascii
    $s13 = "function iaSj(XPcHe) {" fullword ascii
    $s14 = "function Hmrrl(upgWqt) {" fullword ascii
    $s15 = "function qAxTWdpC(gui) {" fullword ascii
    $s16 = "return mhzaZnn(qj,NHUOJ[875-869]+NHUOJ[627-620]+NHUOJ[360-352]);" fullword ascii
    $s17 = "function kfZa(aQNnZ) {" fullword ascii
    $s18 = "function RnvmQSdS(BiEWJ,UFMiTU) {" fullword ascii
    $s19 = "function saogmDVjc(ultVpGlmKsT) {" fullword ascii
    $s20 = "return YwvC.ExpandEnvironmentStrings(dRBgJ);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}