rule sig_20160322_23ea5b1a97e0db33a156b79726248874 {
  meta:
    description = "datamaliciousorder - file 20160322_23ea5b1a97e0db33a156b79726248874.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7249e979e9a7cc0a2da716901f5538fa015cebee3c836425fafbf7f851d8b02"

  strings:
    $s1  = "return WScript.CreateObject(UsCBq);" fullword ascii
    $s2  = "return QUXXYMS[0] + QUXXYMS[2] + QUXXYMS[4] + \".F\" + QUXXYMS[7] + QUXXYMS[9] + QUXXYMS[12] + QUXXYMS[14];" fullword ascii
    $s3  = "var Jp = true  , WzmC = yYQ[7] + yYQ[9] + yYQ[11];" fullword ascii
    $s4  = "var QUXXYMS = vZiAD(YkzhNuRzqT+\" \"+\"System Ve Xspiv Obj GaLrHJ ect WMjfCzY PtpER\", \" \");" fullword ascii
    $s5  = "CfML.open(ioYlI,eoVwT,false);" fullword ascii
    $s6  = "var yYQ = (\"2.XMLHTTP VVqFRDg zTpWK XML ream St SsfWqTKr AD NbAaLfy O jYZU D\").split(\" \");" fullword ascii
    $s7  = "if(i>=E.length) {break;}" fullword ascii
    $s8  = "return NRvb.ExpandEnvironmentStrings(DXFxA);" fullword ascii
    $s9  = "function aTVz(xGTqu) {" fullword ascii
    $s10 = "return CmxfE;" fullword ascii
    $s11 = "return sAK.size;" fullword ascii
    $s12 = "function yISU(MDUvn,eoVwT,ioYlI) {" fullword ascii
    $s13 = "if (xGTqu == 764-564){return true;} else {return false;}" fullword ascii
    $s14 = "function kBxM(gJYnq) {" fullword ascii
    $s15 = "function EPbl(hFOGB) {" fullword ascii
    $s16 = "function CeAOLeA(UKYN) {" fullword ascii
    $s17 = "return new ActiveXObject(gMNeIN);" fullword ascii
    $s18 = "function qWBBztRt(EfOs) {" fullword ascii
    $s19 = "if (sWvnV > 180972-982){return true;} else {return false;}" fullword ascii
    $s20 = "function UCRCm(BBUwbD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}