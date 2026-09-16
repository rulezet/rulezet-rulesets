rule sig_20160405_2712ef0f38849d65a300de0057dd8dc7 {
  meta:
    description = "datamaliciousorder - file 20160405_2712ef0f38849d65a300de0057dd8dc7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "536f0ba7fcff46ed203c73d33f0254eca0218a864c68a9018653096ebae5ca2f"

  strings:
    $s1  = "return yzVJzsv[0] + yzVJzsv[2] + yzVJzsv[4] + \".F\" + yzVJzsv[7] + yzVJzsv[9] + yzVJzsv[12] + yzVJzsv[14];" fullword ascii
    $s2  = "var Ft = true  , eyTj = GmB[7] + GmB[9] + GmB[11];" fullword ascii
    $s3  = "KXzv.open(nNRKK,BzNYu,false);" fullword ascii
    $s4  = "var GmB = (\"2.XMLHTTP pziDdoO wKKbB XML ream St WRKVxSOO AD xRHsbAE O ijvJ D\").split(\" \");" fullword ascii
    $s5  = "if(t>=O.length) {break;}" fullword ascii
    $s6  = "function UuuurBXih(zxusYsVmwFl) {" fullword ascii
    $s7  = "function nnIaFJhb(Vjx) {" fullword ascii
    $s8  = "IEa = t; break; " fullword ascii
    $s9  = "function qRRgfVPNh(yPnMw) {" fullword ascii
    $s10 = "function iQfB(QxqeQ) {" fullword ascii
    $s11 = "if (UuoEF > 152346-266){return true;} else {return false;}" fullword ascii
    $s12 = "return oStQK;" fullword ascii
    $s13 = "if (u >= WXmlo.length) {break;}" fullword ascii
    $s14 = "function hPgokMwl(ddGb) {" fullword ascii
    $s15 = "function ZJAU(fWJEm,hDzLH) {" fullword ascii
    $s16 = "return \"MtOEcWiecNVIYy\";" fullword ascii
    $s17 = "function HbaVy(SLcBGGDR,FDwD) {" fullword ascii
    $s18 = "return EBEcsqv[0];" fullword ascii
    $s19 = "function jkpB(UuoEF) {" fullword ascii
    $s20 = "return new ActiveXObject(jGpV);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}