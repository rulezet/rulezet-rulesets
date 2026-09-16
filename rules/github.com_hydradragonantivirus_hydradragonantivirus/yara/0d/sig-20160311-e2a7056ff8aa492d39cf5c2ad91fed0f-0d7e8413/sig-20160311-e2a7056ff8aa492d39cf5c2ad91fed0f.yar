rule sig_20160311_e2a7056ff8aa492d39cf5c2ad91fed0f {
  meta:
    description = "datamaliciousorder - file 20160311_e2a7056ff8aa492d39cf5c2ad91fed0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "873fb560250755555e2530a4c9a58553b1aea9d52fc4282e5547edc20fbededa"

  strings:
    $s1  = "return todnxFe[0] + todnxFe[2] + todnxFe[4] + \".F\" + todnxFe[7] + todnxFe[9] + todnxFe[12] + todnxFe[14];" fullword ascii
    $s2  = "var aj = true  , jWil = GaB[7] + GaB[9] + GaB[11];" fullword ascii
    $s3  = "aeOzb.open(YFNRy,SpMii,false);" fullword ascii
    $s4  = "LFF.CreateFolder(SOla);" fullword ascii
    $s5  = "var todnxFe = \"Sc jQIjjQz r DchaiYBpm ipting jRKwiWp fOR ile CIspJGQOTeiXaB System nz hKuGn Obj ptbFmC ect tfveyjC\".split(\" " ascii
    $s6  = "var GaB = (\"2.XMLHTTP gsZsgJu YswXi XML ream St zvvtmcfP AD xMwesTP O Rjsf D\").split(\" \");" fullword ascii
    $s7  = "return TxzWV;" fullword ascii
    $s8  = "return LThHuzp" fullword ascii
    $s9  = "function zGoWqgu(yPXr) {" fullword ascii
    $s10 = "return rHXMKGI(hJ,afush[535-529]+afush[725-718]+afush[501-493]);" fullword ascii
    $s11 = "function vDtZeDHS() {" fullword ascii
    $s12 = "function fyYaIBAnj(PzkZyoqDTYD) {" fullword ascii
    $s13 = "function tRDuyyrIS() {" fullword ascii
    $s14 = "function cjRr(veSjG) {" fullword ascii
    $s15 = "function BxEo(VpHGx) {" fullword ascii
    $s16 = "function fqZT(HVGUl) {" fullword ascii
    $s17 = "function rHXMKGI(nvfb,wuMEn) {" fullword ascii
    $s18 = "if (HVGUl > 136563-104){return true;} else {return false;}" fullword ascii
    $s19 = "function mOJx(ZaOut) {" fullword ascii
    $s20 = "function ZqrI(aeOzb,SpMii,YFNRy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}