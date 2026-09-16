rule sig_20160303_41d3d37db2fa1df149730e17f7432af6 {
  meta:
    description = "datamaliciousorder - file 20160303_41d3d37db2fa1df149730e17f7432af6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98c8733e052f6754f377f824b3cf542bcb4e6874e9cf8ce6d7f7615f3af4b6ab"

  strings:
    $s1  = "var BLspY = \"TLbAvv Ixi pt.Shell kSChRkK Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return wS.ExpandEnvironmentStrings(BLspY[6]);" fullword ascii
    $s3  = "var AQ = true  , lIRk = SiQ[7] + \"\" + SiQ[9];" fullword ascii
    $s4  = "return GFCwYFb[0] + GFCwYFb[2] + GFCwYFb[4] + \".F\" + GFCwYFb[7] + GFCwYFb[9] + GFCwYFb[12] + GFCwYFb[14];" fullword ascii
    $s5  = "var SiQ = (tiT + \"TTP\" + \" OoToEzJ LfKDE XML ream St AldNTWoP AD udGPzWe OD\").split(\" \");" fullword ascii
    $s6  = "var GFCwYFb = \"Sc HXvWZIm r EJRTaRdKY ipting zqwnDQI ySv ile PlxteiGKkxQCWN System Hl yyvFZ Obj kxIJHq ect xqfzGsy\".split(\" " ascii
    $s7  = "vnlXe.open(Mglhq,GDcrh,false);" fullword ascii
    $s8  = "function qOmL(aAUDm) {" fullword ascii
    $s9  = "function ySHiCcJDB(iXJupyLdoID) {" fullword ascii
    $s10 = "function USwj(vmIMG) {" fullword ascii
    $s11 = "function OwWJ(nyxkL,ICGdj) {" fullword ascii
    $s12 = "return vTtJ.responseBody;" fullword ascii
    $s13 = "function lLJoW(FuiBGC) {" fullword ascii
    $s14 = "function bEquFrq(kBIl) {" fullword ascii
    $s15 = "return OVzOG;" fullword ascii
    $s16 = "function vgeoYrGhl(ZxQKY,nddhw,vvFVs) {" fullword ascii
    $s17 = "zKI = M; break; " fullword ascii
    $s18 = "if (vmIMG == 1196-996){return true;} else {return false;}" fullword ascii
    $s19 = "function EDjI(YnPap) {" fullword ascii
    $s20 = "function TwaXnQzF() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}