rule sig_20160321_b6d580ea82d8bbb5e8cc817f4c999e49 {
  meta:
    description = "datamaliciousorder - file 20160321_b6d580ea82d8bbb5e8cc817f4c999e49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a56905af77bd487fd8e892c77d615a9988182899fa5dbfe79d97e4a14bdb7749"

  strings:
    $s1  = "return WScript.CreateObject(IsVNa);" fullword ascii
    $s2  = "var CY = true  , tJZs = gLI[7] + gLI[9] + gLI[11];" fullword ascii
    $s3  = "return FltTSXR[0] + FltTSXR[2] + FltTSXR[4] + \".F\" + FltTSXR[7] + FltTSXR[9] + FltTSXR[12] + FltTSXR[14];" fullword ascii
    $s4  = "var FltTSXR = gEkBo(CeNDRaZRKa+\" \"+\"System hF tnAlA Obj BSOBIP ect hxGbZjb JaQLK\", \" \");" fullword ascii
    $s5  = "var gLI = (\"2.XMLHTTP yqUbTze UEiYR XML ream St dsGQCOkN AD FkPgjml O KJDs D\").split(\" \");" fullword ascii
    $s6  = "asHcN.open(Ffowr,nXDsC,false);" fullword ascii
    $s7  = "return gfNfhi.position=509-509;" fullword ascii
    $s8  = "Wjz = Y; break; " fullword ascii
    $s9  = "function WKSxP(gfNfhi) {" fullword ascii
    $s10 = "function kPnRyso(yBxf) {" fullword ascii
    $s11 = "if (l >= LGCkm.length) {break;}" fullword ascii
    $s12 = "function FqOk(asHcN,nXDsC,Ffowr) {" fullword ascii
    $s13 = "return yBxf[puVSGN[0]];" fullword ascii
    $s14 = "function Bkgulga(UiCN,CEHCn) {" fullword ascii
    $s15 = "if (JJEob == 808-608){return true;} else {return false;}" fullword ascii
    $s16 = "return new ActiveXObject(hJAAwk);" fullword ascii
    $s17 = "return Asx.size;" fullword ascii
    $s18 = "function gEkBo(XjW,jbMHb) {" fullword ascii
    $s19 = "function UpZvnPZvy(mftdG) {" fullword ascii
    $s20 = "function KVFnvrXJV(UOrEaQHHZLp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}