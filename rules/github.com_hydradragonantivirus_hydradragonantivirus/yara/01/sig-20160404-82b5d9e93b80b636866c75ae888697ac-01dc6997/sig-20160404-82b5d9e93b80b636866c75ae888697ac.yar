rule sig_20160404_82b5d9e93b80b636866c75ae888697ac {
  meta:
    description = "datamaliciousorder - file 20160404_82b5d9e93b80b636866c75ae888697ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6419c9e934812e15ae73ecbfc34558ee8506c7512045d895e1fb53c9b2b6a403"

  strings:
    $s1  = "function xDogM(fTProS) {" fullword ascii
    $s2  = "var MT = true  , pZDN = REJ[7] + REJ[9] + REJ[11];" fullword ascii
    $s3  = "return hXJATVW[0] + hXJATVW[2] + hXJATVW[4] + \".F\" + hXJATVW[7] + hXJATVW[9] + hXJATVW[12] + hXJATVW[14];" fullword ascii
    $s4  = "var REJ = (\"2.XMLHTTP Fqxhuwh Civjr XML ream St VmUYDVRT AD hodobZO O alrC D\").split(\" \");" fullword ascii
    $s5  = "aqoB.open(jdPmt,HEbvQ,false);" fullword ascii
    $s6  = "return \"SKJeFcBMLSLlbx\";" fullword ascii
    $s7  = "function RpBY(APvmZ,HEbvQ,jdPmt) {" fullword ascii
    $s8  = "function zjMYBU(TIBIqMb) {" fullword ascii
    $s9  = "function VcHS(Ruqbo,udvMT) {" fullword ascii
    $s10 = "function AnnW(WYXUA) {" fullword ascii
    $s11 = "return WDQdxfD;" fullword ascii
    $s12 = "function QjcO(AzFQT) {" fullword ascii
    $s13 = "return pkdVmIN(Os,GQteR[781-775]+GQteR[729-722]+GQteR[850-842]);" fullword ascii
    $s14 = "function QKNBAE(ggkE,IiqFcR) {" fullword ascii
    $s15 = "function SzAjijNew(MtkDxhPHfUe) {" fullword ascii
    $s16 = "function uZgG(gcuqe) {" fullword ascii
    $s17 = "if (UNicu > 181692-886){return true;} else {return false;}" fullword ascii
    $s18 = "Atd = e; break; " fullword ascii
    $s19 = "function qTvhtKcb(MqU) {" fullword ascii
    $s20 = "if(e>=L.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}