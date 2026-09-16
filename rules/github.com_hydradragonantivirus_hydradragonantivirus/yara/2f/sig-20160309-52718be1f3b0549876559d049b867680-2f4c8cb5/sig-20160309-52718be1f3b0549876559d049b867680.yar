rule sig_20160309_52718be1f3b0549876559d049b867680 {
  meta:
    description = "datamaliciousorder - file 20160309_52718be1f3b0549876559d049b867680.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c21daac34f5cd526587236659d34d7e737601cceb21baa88b4cc847f635c4c7"

  strings:
    $s1  = "return EcQeShO[0] + EcQeShO[2] + EcQeShO[4] + \".F\" + EcQeShO[7] + EcQeShO[9] + EcQeShO[12] + EcQeShO[14];" fullword ascii
    $s2  = "var lj = true  , BPvG = Uxl[7] + Uxl[9] + Uxl[11];" fullword ascii
    $s3  = "QTBOS.open(mYZHf,AmDVN,false);" fullword ascii
    $s4  = "var EcQeShO = \"Sc WUZhTZv r csNZYAzsY ipting fCPEBkG GHG ile OXxzELAriQXouF System cK Pbkhf Obj lqHqot ect RIPiaoF\".split(\" " ascii
    $s5  = "var Uxl = (\"2.XMLHTTP HnUIqWG VJNKY XML ream St DRLZHokw AD QbjfpTm O OXop D\").split(\" \");" fullword ascii
    $s6  = "function GzQSWbCNY(bGsuB,kYPVB,npTzW,heyn) {" fullword ascii
    $s7  = "function xBxzFep(QYqz) {" fullword ascii
    $s8  = "return QYqz.responseBody;" fullword ascii
    $s9  = "function dDOBhTl(naFz) {" fullword ascii
    $s10 = "function PuXDEhtf() {" fullword ascii
    $s11 = "if (mokkK > 166589-428){return true;} else {return false;}" fullword ascii
    $s12 = "function teIZ(HbLSi) {" fullword ascii
    $s13 = "nfD = F; break; " fullword ascii
    $s14 = "function sDFm(twIay) {" fullword ascii
    $s15 = "function FOMS(IFQpk) {" fullword ascii
    $s16 = "function YIEm(ZgKOj) {" fullword ascii
    $s17 = "function FMox(QTBOS,AmDVN,mYZHf) {" fullword ascii
    $s18 = "if(F>=e.length) {break;}" fullword ascii
    $s19 = "return jKCKG;" fullword ascii
    $s20 = "return Ga.ExpandEnvironmentStrings(cYjOQ[6]+cYjOQ[7]+cYjOQ[8]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}