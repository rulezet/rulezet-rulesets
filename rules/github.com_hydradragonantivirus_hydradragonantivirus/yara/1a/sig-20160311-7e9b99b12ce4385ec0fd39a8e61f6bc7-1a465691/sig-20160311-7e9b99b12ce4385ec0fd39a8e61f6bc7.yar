rule sig_20160311_7e9b99b12ce4385ec0fd39a8e61f6bc7 {
  meta:
    description = "datamaliciousorder - file 20160311_7e9b99b12ce4385ec0fd39a8e61f6bc7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa57598fa1c4307d8cf0fb92b6a63d533e63366c2173f2c595738b7df7705682"

  strings:
    $s1  = "var Oy = true  , xMsT = Xuy[7] + Xuy[9] + Xuy[11];" fullword ascii
    $s2  = "return hsoFJNX[0] + hsoFJNX[2] + hsoFJNX[4] + \".F\" + hsoFJNX[7] + hsoFJNX[9] + hsoFJNX[12] + hsoFJNX[14];" fullword ascii
    $s3  = "FDdtP.open(wgRsr,KCwvw,false);" fullword ascii
    $s4  = "var Xuy = (\"2.XMLHTTP waONqxU SCcpp XML ream St lwwmAacr AD VmCfhQA O FtyE D\").split(\" \");" fullword ascii
    $s5  = "var hsoFJNX = \"Sc JaSlLiz r BRQXtefDb ipting BREzsnh QHS ile cPUhuhcrNxxYDM System uZ CrHQp Obj ECDhcm ect cMbEPGS\".split(\" " ascii
    $s6  = "return sKB.size;" fullword ascii
    $s7  = "return uoNIxy.position=449-449;" fullword ascii
    $s8  = "return ATOzfCr" fullword ascii
    $s9  = "return IlHAH;" fullword ascii
    $s10 = "function nIhMNdAb(sKB) {" fullword ascii
    $s11 = "return EvLg.responseBody;" fullword ascii
    $s12 = "function cfix(hXcwa) {" fullword ascii
    $s13 = "function FtjD(vlPYC,TCJQl) {" fullword ascii
    $s14 = "if(T>=O.length) {break;}" fullword ascii
    $s15 = "function KGmPbUqw() {" fullword ascii
    $s16 = "function WTGU(bUPaH,sNwPh) {" fullword ascii
    $s17 = "function NBPDaxc(pCXf,PpruX) {" fullword ascii
    $s18 = "function AmTKDUXGx() {" fullword ascii
    $s19 = "function xHaFXtx(EvLg) {" fullword ascii
    $s20 = "function FQFa(SDbpJ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}