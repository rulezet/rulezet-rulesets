rule sig_20160301_ce41cbbac8bd74793d14183f01db348f {
  meta:
    description = "datamaliciousorder - file 20160301_ce41cbbac8bd74793d14183f01db348f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a53f9edecffdfa73d81c9e0ffaf6c5207b70ce27044e78615f5f7a45cc6b709d"

  strings:
    $s1  = "var oL = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(zNKFU);" fullword ascii
    $s3  = "var XoW = (SGh + \"TTP\" + \" FdQQBzv kFfDD XML ream St mmGFSqyK AD CRFBprL OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + frwklnW + \".F\" + MWEiIHmDyL + SuDdQ + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var OW = true  , FRjt = XoW[7] + \"\" + XoW[9];" fullword ascii
    $s6  = "DFjgt.open(DWKuo,unQGD,false);" fullword ascii
    $s7  = "function soSX(nLujP) {" fullword ascii
    $s8  = "return oHUqv;" fullword ascii
    $s9  = "if (((new Date())>0,7395869888)) {" fullword ascii
    $s10 = "function gMzP(HWvKV,ViMvs) {" fullword ascii
    $s11 = "if (OZKNa == 898-698){return true;} else {return false;}" fullword ascii
    $s12 = "if (llIMv > 182318-348){return true;} else {return false;}" fullword ascii
    $s13 = "function ssIi(OZKNa) {" fullword ascii
    $s14 = "function BTCR(llIMv) {" fullword ascii
    $s15 = "function KXCp(usobE,Pfwlm) {" fullword ascii
    $s16 = "function inYTo(upFUmz) {" fullword ascii
    $s17 = "if(U>=S.length) {break;}" fullword ascii
    $s18 = "function CyMx(FsDRR) {" fullword ascii
    $s19 = "return tW.ExpandEnvironmentStrings(oL);" fullword ascii
    $s20 = "function sioO(DFjgt,unQGD,DWKuo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}