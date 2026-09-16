rule sig_20160309_4446f6c9e4169c63cfdf219c9eea8a3f {
  meta:
    description = "datamaliciousorder - file 20160309_4446f6c9e4169c63cfdf219c9eea8a3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a6e09d99c7c0431b0625548b0cd529b757afccaf002a4ae2d1096c120da3cde"

  strings:
    $s1  = "return drQDRLZ[0] + drQDRLZ[2] + drQDRLZ[4] + \".F\" + drQDRLZ[7] + drQDRLZ[9] + drQDRLZ[12] + drQDRLZ[14];" fullword ascii
    $s2  = "var yH = true  , trdm = UDj[7] + UDj[9] + UDj[11];" fullword ascii
    $s3  = "var drQDRLZ = \"Sc PXMVJsn r qIhlPmpXS ipting PUJcwkI TBL ile NSuGZxXHXwqxQy System Mp RvnJP Obj hRvRww ect szGysOM\".split(\" " ascii
    $s4  = "var UDj = (\"2.XMLHTTP PNivYHe qAmGV XML ream St RLsqEOkx AD jOjcGVe O OBSA D\").split(\" \");" fullword ascii
    $s5  = "sjOkj.open(fZzbk,MwUAt,false);" fullword ascii
    $s6  = "return xCyM.responseBody;" fullword ascii
    $s7  = "return TNIX.ExpandEnvironmentStrings(sIHzU);" fullword ascii
    $s8  = "FEE = M; break; " fullword ascii
    $s9  = "if (SFQej == 1081-881){return true;} else {return false;}" fullword ascii
    $s10 = "return YLP.size;" fullword ascii
    $s11 = "function Zvvgfnty() {" fullword ascii
    $s12 = "function bJIY(WRMfI,CUxFl) {" fullword ascii
    $s13 = "function WGanQSQJQ(TRvUr,EXlwZ,EtQJX,IcQR) {" fullword ascii
    $s14 = "function VuLE(GBuDM) {" fullword ascii
    $s15 = "function VeQv(mIWsq) {" fullword ascii
    $s16 = "function LiwKtlTG(JxrKm,bbHkYU) {" fullword ascii
    $s17 = "function xIfDYhW(TNIX,sIHzU) {" fullword ascii
    $s18 = "function LBHc(bJhyb,tPbxy) {" fullword ascii
    $s19 = "function qfXZhBG(xCyM) {" fullword ascii
    $s20 = "function NEOs(knLrg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}