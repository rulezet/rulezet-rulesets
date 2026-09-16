rule sig_20160324_7615284fe988d548bb934a5c92523c86 {
  meta:
    description = "datamaliciousorder - file 20160324_7615284fe988d548bb934a5c92523c86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0d8947044768446e0dad611e0e69f73920bcf539531a21aaf2111c9c001f594"

  strings:
    $s1  = "return WScript.CreateObject(QsWNK);" fullword ascii
    $s2  = "var SY = true  , yPOo = QIR[7] + QIR[9] + QIR[11];" fullword ascii
    $s3  = "return HoTTjWs[0] + HoTTjWs[2] + HoTTjWs[4] + \".F\" + HoTTjWs[7] + HoTTjWs[9] + HoTTjWs[12] + HoTTjWs[14];" fullword ascii
    $s4  = "var QIR = (\"2.XMLHTTP HpugCQR GkzyL XML ream St EUGcSdcd AD ztdkLXK O qLOt D\").split(\" \");" fullword ascii
    $s5  = "PolZ.open(vDsxG,BnBSF,false);" fullword ascii
    $s6  = "var HoTTjWs = ERFNf(CBKZUVXdiD+\" \"+\"System PQ qFuDA Obj zHGIge ect yaqbsEl ZtEbc\", \" \");" fullword ascii
    $s7  = "if(E>=W.length) {break;}" fullword ascii
    $s8  = "return yVTup;" fullword ascii
    $s9  = "function yegp(OnJAr) {" fullword ascii
    $s10 = "function vyWb(OitCk) {" fullword ascii
    $s11 = "function HIVn(KdKuz) {" fullword ascii
    $s12 = "return TSKm.ExpandEnvironmentStrings(rzFgH);" fullword ascii
    $s13 = "function NlGg(bWerc) {" fullword ascii
    $s14 = "function DBOUzJX(TSKm,rzFgH) {" fullword ascii
    $s15 = "return QcFGvl/*SKrHEgBTRakiFWLuiFroRud3Z*/.position=685-685;" fullword ascii
    $s16 = "function oAkb(dYcDl,SZmAv) {" fullword ascii
    $s17 = "function GtLDRPFA(qkk) {" fullword ascii
    $s18 = "function sFGyS(JGFnaJrH,DOkq) {" fullword ascii
    $s19 = "function RtZCSTFMO(lUzDfMWUzBC) {" fullword ascii
    $s20 = "function PryqegIH(JLuD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}