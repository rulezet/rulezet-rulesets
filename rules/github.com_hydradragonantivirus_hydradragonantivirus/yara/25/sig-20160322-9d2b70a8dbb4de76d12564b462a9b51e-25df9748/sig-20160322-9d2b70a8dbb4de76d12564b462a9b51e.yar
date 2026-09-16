rule sig_20160322_9d2b70a8dbb4de76d12564b462a9b51e {
  meta:
    description = "datamaliciousorder - file 20160322_9d2b70a8dbb4de76d12564b462a9b51e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f671a719cfa4771450b47a2b51390188009d697dc6c724a80f5250cb6af1bd15"

  strings:
    $s1  = "return WScript.CreateObject(TRxDE);" fullword ascii
    $s2  = "var Gq = true  , VXbr = kai[7] + kai[9] + kai[11];" fullword ascii
    $s3  = "return TluMXCE[0] + TluMXCE[2] + TluMXCE[4] + \".F\" + TluMXCE[7] + TluMXCE[9] + TluMXCE[12] + TluMXCE[14];" fullword ascii
    $s4  = "var TluMXCE = aaIrh(XPSjFPcJOx+\" \"+\"System xH pqUeX Obj OxndZq ect joONLzp MSOTx\", \" \");" fullword ascii
    $s5  = "IvjQ.open(YUydM,xCDXi,false);" fullword ascii
    $s6  = "var kai = (\"2.XMLHTTP qttMrEM RNkkf XML ream St xjqVIoWW AD wNHJzTX O tBdp D\").split(\" \");" fullword ascii
    $s7  = "NYa = O; break; " fullword ascii
    $s8  = "return new ActiveXObject(nqOlGM);" fullword ascii
    $s9  = "function Fvif(TRxDE) {" fullword ascii
    $s10 = "function biEOG(cBzYie) {" fullword ascii
    $s11 = "function plkr(jgAhp) {" fullword ascii
    $s12 = "function ATWGdoG(JCdW) {" fullword ascii
    $s13 = "return ZnHJYzr(Gx,GrWvl[365-359]+GrWvl[431-424]+GrWvl[338-330]);" fullword ascii
    $s14 = "function ytXM(hRTzP) {" fullword ascii
    $s15 = "function WbhHi(nqOlGM) {" fullword ascii
    $s16 = "function yMVr(XNeoh,xCDXi,YUydM) {" fullword ascii
    $s17 = "return JCdW[CdRMiC[0]];" fullword ascii
    $s18 = "function aaIrh(Kmg,WxnVX) {" fullword ascii
    $s19 = "function RaxVzKyuR(VYJgKhEBvvH) {" fullword ascii
    $s20 = "function diRH(rIDEN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}