rule sig_20160309_59a715d372a66674c1f99c768a029704 {
  meta:
    description = "datamaliciousorder - file 20160309_59a715d372a66674c1f99c768a029704.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e32ae5bb3cc7a0f91711416c614813f37b3f7dfb377f114169a4633127d8d0b"

  strings:
    $s1  = "var tU = true  , uGtz = krH[7] + krH[9] + krH[11];" fullword ascii
    $s2  = "return WgcnLqu[0] + WgcnLqu[2] + WgcnLqu[4] + \".F\" + WgcnLqu[7] + WgcnLqu[9] + WgcnLqu[12] + WgcnLqu[14];" fullword ascii
    $s3  = "var WgcnLqu = \"Sc GsPIGhG r TihxctJxJ ipting QlxuhQz EjK ile FMXFFQVNqkZAaQ System DQ NVhfo Obj XKDXwE ect oJMWzjV\".split(\" " ascii
    $s4  = "uPjBq.open(XFVfa,bStzR,false);" fullword ascii
    $s5  = "var krH = (\"2.XMLHTTP OqOMmbg Ivgub XML ream St ukxEtFnq AD zpdrbeY O fUKb D\").split(\" \");" fullword ascii
    $s6  = "function ZeZStnK(qkiG,ZNfdO) {" fullword ascii
    $s7  = "function BKkPOkwTF(pSPcSHArAxJ) {" fullword ascii
    $s8  = "function UVaM(EneiC) {" fullword ascii
    $s9  = "return TVPSoEh" fullword ascii
    $s10 = "function XmWU(uPjBq,bStzR,XFVfa) {" fullword ascii
    $s11 = "return RRLF.responseBody;" fullword ascii
    $s12 = "if (g >= GxFsV.length) {break;}" fullword ascii
    $s13 = "function efnu(iMIIy) {" fullword ascii
    $s14 = "function sDqU(apujD) {" fullword ascii
    $s15 = "function cfIdA(rvQuKf) {" fullword ascii
    $s16 = "return dGCGE;" fullword ascii
    $s17 = "return new ActiveXObject(rvQuKf);" fullword ascii
    $s18 = "function SWxA(GxFsV) {" fullword ascii
    $s19 = "function UWGp(cbxsS) {" fullword ascii
    $s20 = "if (apujD > 196054-188){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}