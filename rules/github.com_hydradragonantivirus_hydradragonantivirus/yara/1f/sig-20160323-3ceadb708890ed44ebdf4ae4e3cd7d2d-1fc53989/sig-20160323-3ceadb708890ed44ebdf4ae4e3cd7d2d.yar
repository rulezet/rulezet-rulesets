rule sig_20160323_3ceadb708890ed44ebdf4ae4e3cd7d2d {
  meta:
    description = "datamaliciousorder - file 20160323_3ceadb708890ed44ebdf4ae4e3cd7d2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "049a150e59350feddbb6204367709a62c34d7369fe3f38db3e4e4ead41e04a86"

  strings:
    $s1  = "return WScript.CreateObject(UiQHW);" fullword ascii
    $s2  = "return LdCCGAV[0] + LdCCGAV[2] + LdCCGAV[4] + \".F\" + LdCCGAV[7] + LdCCGAV[9] + LdCCGAV[12] + LdCCGAV[14];" fullword ascii
    $s3  = "var ws = true  , YEZE = PVR[7] + PVR[9] + PVR[11];" fullword ascii
    $s4  = "var LdCCGAV = WTIxg(iHUxqbPZGf+\" \"+\"System yk PEYtS Obj UbhZzG ect zVGkNfN cGAQh\", \" \");" fullword ascii
    $s5  = "var PVR = (\"2.XMLHTTP ThLTYYD ZOaAM XML ream St MAwWKcUE AD OWuyJtA O xsXs D\").split(\" \");" fullword ascii
    $s6  = "Wfqg.open(uWXfB,SJHSt,false);" fullword ascii
    $s7  = "if(T>=h.length) {break;}" fullword ascii
    $s8  = "function edLp(jDnii,AHWWR) {" fullword ascii
    $s9  = "function LREKmVF(VHGo,XfwPP) {" fullword ascii
    $s10 = "function USTo(DTJUD) {" fullword ascii
    $s11 = "function UJUImjCW(cof) {" fullword ascii
    $s12 = "if (DTJUD == 1160-960){return true;} else {return false;}" fullword ascii
    $s13 = "function uZgdfpRyG(fNPpQiTNVYe) {" fullword ascii
    $s14 = "return XfjUSp/*VUdmea5488U8HNdDkcQui85ms*/.position=641-641;" fullword ascii
    $s15 = "function kZxnTPIPO(uYZlR) {" fullword ascii
    $s16 = "function Dfcsf(XfjUSp) {" fullword ascii
    $s17 = "function DbXf(TlFQR) {" fullword ascii
    $s18 = "function FqqPT(Zlibky) {" fullword ascii
    $s19 = "function JAmh(tUVHX) {" fullword ascii
    $s20 = "function GAWa(uRQxT,SJHSt,uWXfB) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}