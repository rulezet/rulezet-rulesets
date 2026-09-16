rule sig_20160308_e54a6fe8d356e0b9135419a32acd68bf {
  meta:
    description = "datamaliciousorder - file 20160308_e54a6fe8d356e0b9135419a32acd68bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cee1cb35a5b741227407fbd92d9fe075dc0510f34e3d8e78c541af5d565da9d1"

  strings:
    $s1  = "var iQ = true  , enwF = roc[7] + roc[9] + roc[11];" fullword ascii
    $s2  = "return EOmOESU[0] + EOmOESU[2] + EOmOESU[4] + \".F\" + EOmOESU[7] + EOmOESU[9] + EOmOESU[12] + EOmOESU[14];" fullword ascii
    $s3  = "var roc = (\"2.XMLHTTP hjBwjef BWZFe XML ream St vKRgndfU AD sJFpyQl O hNgg D\").split(\" \");" fullword ascii
    $s4  = "ipAxf.open(yiHsY,HqMWe,false);" fullword ascii
    $s5  = "if(h>=A.length) {break;}" fullword ascii
    $s6  = "function ZUETw(xoMcVh) {" fullword ascii
    $s7  = "function QnoAKDRM(zfh) {" fullword ascii
    $s8  = "function XUUL(rjjpX,mwbSE) {" fullword ascii
    $s9  = "function PWxm(NufiJ) {" fullword ascii
    $s10 = "if (((new Date())>0,7454470888)) {" fullword ascii
    $s11 = "return jZ.ExpandEnvironmentStrings(YERCm[6]+YERCm[7]+YERCm[8]);" fullword ascii
    $s12 = "function hPSh(jJBZh) {" fullword ascii
    $s13 = "function AwKOCSMec(AGKeVnTjgjF) {" fullword ascii
    $s14 = "function Drdp(rAhXD,RpNmn) {" fullword ascii
    $s15 = "function JCRk(rLbRr) {" fullword ascii
    $s16 = "function FFHX(AxUZz) {" fullword ascii
    $s17 = "return RISEn;" fullword ascii
    $s18 = "function WeZngsaL() {" fullword ascii
    $s19 = "function snRmetMBY(dDVxC,cRwPv,nImWE,YHZS) {" fullword ascii
    $s20 = "function rKlw(jbNMH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}