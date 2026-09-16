rule sig_20160302_1a4d7e0a0ca5b0723bc7ecfbab8af9a4 {
  meta:
    description = "datamaliciousorder - file 20160302_1a4d7e0a0ca5b0723bc7ecfbab8af9a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b2ab2f71111b88c75573976823e33ce8c5f57d93428b77b99216f4175d0fa30"

  strings:
    $s1  = "var cl = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(fxFpt);" fullword ascii
    $s3  = "var ED = true  , tOCh = cjL[7] + \"\" + cjL[9];" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + sWNVmqY + \".F\" + XUQCeXkmha + xYGlz + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var cjL = (xLa + \"TTP\" + \" TKdyuVS fQHTE XML ream St amRiEHzA AD iqoWwTz OD\").split(\" \");" fullword ascii
    $s6  = "nxYXm.open(zCLlj,LKKFz,false);" fullword ascii
    $s7  = "if (HXROF == 377-177){return true;} else {return false;}" fullword ascii
    $s8  = "function mWuJ(KXWzL,uCyYT) {" fullword ascii
    $s9  = "return new ActiveXObject(zEsJGb);" fullword ascii
    $s10 = "function tpYc(JZIMR) {" fullword ascii
    $s11 = "function wCqiosxAF(gOQjg,AbNka,GTPGi) {" fullword ascii
    $s12 = "oTN = I; break; " fullword ascii
    $s13 = "return yGMBv;" fullword ascii
    $s14 = "function lwuH(nxYXm,LKKFz,zCLlj) {" fullword ascii
    $s15 = "function eYsD(SOxyD) {" fullword ascii
    $s16 = "return JZIMR.status;" fullword ascii
    $s17 = "function OXXH(DXovu,rsgHW) {" fullword ascii
    $s18 = "function cogl(HXROF) {" fullword ascii
    $s19 = "function cfXt(McsBR) {" fullword ascii
    $s20 = "if (cFqvV > 174524-474){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}