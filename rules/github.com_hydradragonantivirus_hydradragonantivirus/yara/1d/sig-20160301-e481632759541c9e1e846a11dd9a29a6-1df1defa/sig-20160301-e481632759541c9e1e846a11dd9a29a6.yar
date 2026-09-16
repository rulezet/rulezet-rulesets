rule sig_20160301_e481632759541c9e1e846a11dd9a29a6 {
  meta:
    description = "datamaliciousorder - file 20160301_e481632759541c9e1e846a11dd9a29a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d5132c0e03cd965911af046e1c2a54d6761bcd1a5e6cfeeb569c5050bbf956c"

  strings:
    $s1  = "var Sd = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(IBATl);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + iwECliO + \".F\" + sZztZIcEuu + FDbEE + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var sdh = (Tqm + \"TTP\" + \" GAcIkPJ GMNSJ XML ream St rfJAzIBQ AD HBmkJMS OD\").split(\" \");" fullword ascii
    $s5  = "var jv = true  , liQx = sdh[7] + \"\" + sdh[9];" fullword ascii
    $s6  = "EErSz.open(bijcF,cHxsd,false);" fullword ascii
    $s7  = "return Vg.ExpandEnvironmentStrings(Sd);" fullword ascii
    $s8  = "if (sCyCq > 182239-322){return true;} else {return false;}" fullword ascii
    $s9  = "function PZSl(ewyTA) {" fullword ascii
    $s10 = "return new ActiveXObject(nGCzKS);" fullword ascii
    $s11 = "function gQPVglhfz(yenaG,CZSMh,uDVej) {" fullword ascii
    $s12 = "return DGRro.status;" fullword ascii
    $s13 = "function jxZV(sCyCq) {" fullword ascii
    $s14 = "Jkp = e; break; " fullword ascii
    $s15 = "if (((new Date())>0,7450618888)) {" fullword ascii
    $s16 = "return Cuflp;" fullword ascii
    $s17 = "function eXRi(uRbLY) {" fullword ascii
    $s18 = "function rgTK(moqLD,EeNgc) {" fullword ascii
    $s19 = "if (uRbLY == 593-393){return true;} else {return false;}" fullword ascii
    $s20 = "function jBiV(jIrGw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}