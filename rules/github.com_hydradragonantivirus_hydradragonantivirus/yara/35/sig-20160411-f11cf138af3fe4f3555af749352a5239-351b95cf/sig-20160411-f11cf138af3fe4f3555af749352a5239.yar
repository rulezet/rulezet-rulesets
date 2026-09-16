rule sig_20160411_f11cf138af3fe4f3555af749352a5239 {
  meta:
    description = "datamaliciousorder - file 20160411_f11cf138af3fe4f3555af749352a5239.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dfcde5981555b819344ad23988e555600823dc31e20addfce54c2e8dfb09202"

  strings:
    $s1  = "function BsGPV(DwsPYV) {" fullword ascii
    $s2  = "var zY = true  , PYMr = bRR[7] + bRR[9] + bRR[11];" fullword ascii
    $s3  = "return nKvVZnv[0] + nKvVZnv[2] + nKvVZnv[4] + \".F\" + nKvVZnv[7] + nKvVZnv[9] + nKvVZnv[12] + nKvVZnv[14];" fullword ascii
    $s4  = "var bRR = (\"2.XMLHTTP eDPJbDc iklPx XML ream St PbDDscTo AD hCYcBqK O DBOz D\").split(\" \");" fullword ascii
    $s5  = "dNrb.open(aLbBX,jlcVz,false);" fullword ascii
    $s6  = "function NHeQV(Mtu,CWbUK) {" fullword ascii
    $s7  = "return khVxO;" fullword ascii
    $s8  = "EYl = n; break; " fullword ascii
    $s9  = "function xJlx(XmtlM) {" fullword ascii
    $s10 = "function nDFxYQU(MDVk) {" fullword ascii
    $s11 = "function qTgZ(IdCDP) {" fullword ascii
    $s12 = "return MDVk[ldHflsS[0]+ldHflsS[1]];" fullword ascii
    $s13 = "function CvJONJD(Sezd,EmoLo) {" fullword ascii
    $s14 = "function cicxye(BXUO,wHJoWw) {" fullword ascii
    $s15 = "return ORS.size;" fullword ascii
    $s16 = "function XDBQ(vkADQ) {" fullword ascii
    $s17 = "function ggIf(BKjnu) {" fullword ascii
    $s18 = "return CvJONJD(ix,EDqVnD+VVAAW[687-679]);" fullword ascii
    $s19 = "return ozcBNPM;" fullword ascii
    $s20 = "function uGOJ(FrKAp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}