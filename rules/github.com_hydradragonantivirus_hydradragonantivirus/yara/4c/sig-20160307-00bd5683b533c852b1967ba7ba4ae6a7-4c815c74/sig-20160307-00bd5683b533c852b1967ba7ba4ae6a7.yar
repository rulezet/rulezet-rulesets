rule sig_20160307_00bd5683b533c852b1967ba7ba4ae6a7 {
  meta:
    description = "datamaliciousorder - file 20160307_00bd5683b533c852b1967ba7ba4ae6a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40e7211e31251a582d8aa6a32f936ebb2adfe0ce09f8c40d7ce0e462a5e5b9c5"

  strings:
    $s1  = "return tBrrVFE[0] + tBrrVFE[2] + tBrrVFE[4] + \".F\" + tBrrVFE[7] + tBrrVFE[9] + tBrrVFE[12] + tBrrVFE[14];" fullword ascii
    $s2  = "var Ga = true  , bCBS = Nlh[7] + Nlh[9] + Nlh[11];" fullword ascii
    $s3  = "var Nlh = (\"2.XMLHTTP fRQgJtx zcHnR XML ream St PLqIVzwB AD tcgRCDr O kGeO D\").split(\" \");" fullword ascii
    $s4  = "eDZUH.open(nfQrU,wVIqH,false);" fullword ascii
    $s5  = "var tBrrVFE = \"Sc AQEFFwQ r wLFQJPzEE ipting UXDDHSv UsB ile pddOeVnSJyquiR System oV FGuQZ Obj EDBgTA ect LSAJlLC\".split(\" " ascii
    $s6  = "function PrwV(eDZUH,wVIqH,nfQrU) {" fullword ascii
    $s7  = "return Jq.ExpandEnvironmentStrings(WTJlG[6]+WTJlG[7]+WTJlG[8]);" fullword ascii
    $s8  = "function VDfS(wfTzn) {" fullword ascii
    $s9  = "return Bht.size;" fullword ascii
    $s10 = "if(y>=p.length) {break;}" fullword ascii
    $s11 = "function piyC(TNwtu) {" fullword ascii
    $s12 = "function djzzPvXHK(JTzThmhvInm) {" fullword ascii
    $s13 = "return new ActiveXObject(DNAABA);" fullword ascii
    $s14 = "function tDAcw(DNAABA) {" fullword ascii
    $s15 = "if (eGSDX == 998-798){return true;} else {return false;}" fullword ascii
    $s16 = "function LNttiVjB() {" fullword ascii
    $s17 = "function RbHi(XMKcp,mlZvQ) {" fullword ascii
    $s18 = "lYr = y; break; " fullword ascii
    $s19 = "return wfTzn.status;" fullword ascii
    $s20 = "if (f >= ufxYz.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}