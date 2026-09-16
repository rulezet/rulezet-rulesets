rule sig_20160314_d716595420e288a7b5ea45ca315da064 {
  meta:
    description = "datamaliciousorder - file 20160314_d716595420e288a7b5ea45ca315da064.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4474ecc18aff3f1cd7ff93012b488f3f011457fcd25e01ea3a59e4b213cbc0a1"

  strings:
    $s1  = "return VPVYoEx[0] + VPVYoEx[2] + VPVYoEx[4] + \".F\" + VPVYoEx[7] + VPVYoEx[9] + VPVYoEx[12] + VPVYoEx[14];" fullword ascii
    $s2  = "var wX = true  , USWB = TxN[7] + TxN[9] + TxN[11];" fullword ascii
    $s3  = "var VPVYoEx = \"Sc WjKhlbW r scFDGLXsM ipting xjNekvg pAm ile AUiTlSbKBEPkEk System an mpQzB Obj EqREkJ ect cUnMewp IwOpT\".spli" ascii
    $s4  = "RpffT.open(Pywoj,quKlI,false);" fullword ascii
    $s5  = "var VPVYoEx = \"Sc WjKhlbW r scFDGLXsM ipting xjNekvg pAm ile AUiTlSbKBEPkEk System an mpQzB Obj EqREkJ ect cUnMewp IwOpT\".spli" ascii
    $s6  = "var TxN = (\"2.XMLHTTP RoocKGi hxrkL XML ream St sAMfYvtH AD ZuUtUyW O PsNo D\").split(\" \");" fullword ascii
    $s7  = "function QDqE(ZEzDW) {" fullword ascii
    $s8  = "if (xBMhZ > 150987-972){return true;} else {return false;}" fullword ascii
    $s9  = "return sBVA.responseBody;" fullword ascii
    $s10 = "return iBGF.ExpandEnvironmentStrings(UUpyq);" fullword ascii
    $s11 = "function esShyKzLK() {" fullword ascii
    $s12 = "function lSAr(SOFUz) {" fullword ascii
    $s13 = "function RuAYkYf(iBGF,UUpyq) {" fullword ascii
    $s14 = "if(h>=j.length) {break;}" fullword ascii
    $s15 = "if (F >= TqYEf.length) {break;}" fullword ascii
    $s16 = "return HLYLPr.position=904-904;" fullword ascii
    $s17 = "return yJw.size;" fullword ascii
    $s18 = "function FOCq(jCSIK) {" fullword ascii
    $s19 = "function spwfFFBB() {" fullword ascii
    $s20 = "function RyoWkXb(sBVA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}