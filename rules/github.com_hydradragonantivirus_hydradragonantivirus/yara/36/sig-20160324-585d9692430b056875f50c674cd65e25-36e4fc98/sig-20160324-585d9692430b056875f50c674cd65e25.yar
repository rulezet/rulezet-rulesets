rule sig_20160324_585d9692430b056875f50c674cd65e25 {
  meta:
    description = "datamaliciousorder - file 20160324_585d9692430b056875f50c674cd65e25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "490a90c12688315acd7cf3640bd0b03ca58edcf06ebbf8e354cd68cfee2b4747"

  strings:
    $s1  = "return WScript.CreateObject(xNimS);" fullword ascii
    $s2  = "var qP = true  , iiEr = jEE[7] + jEE[9] + jEE[11];" fullword ascii
    $s3  = "return gNwvLZq[0] + gNwvLZq[2] + gNwvLZq[4] + \".F\" + gNwvLZq[7] + gNwvLZq[9] + gNwvLZq[12] + gNwvLZq[14];" fullword ascii
    $s4  = "return ebQuhi/*lAClNAqR2rWgqvs9dmIwcmD6Q*/.position=778-778;" fullword ascii
    $s5  = "REqF.open(piguY,zOwpl,false);" fullword ascii
    $s6  = "var gNwvLZq = Fpbts(rQrDiVqTTw+\" \"+\"System pl QbPuN Obj fHZsHy ect eeEFuQL iaQlm\", \" \");" fullword ascii
    $s7  = "var jEE = (\"2.XMLHTTP ahRJiLw tZHfN XML ream St wZLuTUaZ AD jCWOERE O HDqE D\").split(\" \");" fullword ascii
    $s8  = "function uIErVXrYs(SrHPSFHUOCl) {" fullword ascii
    $s9  = "return SLp.size;" fullword ascii
    $s10 = "function Fpbts(YJz,ZdLPh) {" fullword ascii
    $s11 = "function soqL(CLwTF) {" fullword ascii
    $s12 = "return mWjjr.status;" fullword ascii
    $s13 = "var WMTtYlc = \"ejBZvp*gdG*pt.S\"+\"hell*cnEsIPJ*Scri*\";" fullword ascii
    $s14 = "function mtCrCttX(Ruhb) {" fullword ascii
    $s15 = "function xBvy(yDHCx,zOwpl,piguY) {" fullword ascii
    $s16 = "function msKE(NMdoD) {" fullword ascii
    $s17 = "function PzBxidpp(SLp) {" fullword ascii
    $s18 = "return cJAES;" fullword ascii
    $s19 = "if (CLwTF > 195672-286){return true;} else {return false;}" fullword ascii
    $s20 = "function syGhV(ebQuhi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}