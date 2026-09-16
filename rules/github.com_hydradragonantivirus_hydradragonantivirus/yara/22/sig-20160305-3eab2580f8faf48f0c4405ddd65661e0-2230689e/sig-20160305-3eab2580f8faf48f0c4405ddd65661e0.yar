rule sig_20160305_3eab2580f8faf48f0c4405ddd65661e0 {
  meta:
    description = "datamaliciousorder - file 20160305_3eab2580f8faf48f0c4405ddd65661e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76fd42de29cd9b29d84ff9e794c405298ba548c6106e37507b95d31a6f5bd2ca"

  strings:
    $s1  = "var bDHfZ = \"Xmseke PHy pt.Shell BsznTqx Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var FX = true  , EFxN = PSE[7] + \"\" + PSE[9];" fullword ascii
    $s3  = "var PSE = (qew + \"TTP\" + \" PCwFIhW LZldL XML ream St rEwkYGJp AD bdYitrr OD\").split(\" \");" fullword ascii
    $s4  = "return FnAcnPa[0] + FnAcnPa[2] + FnAcnPa[4] + \".F\" + FnAcnPa[7] + FnAcnPa[9] + FnAcnPa[12] + FnAcnPa[14];" fullword ascii
    $s5  = "var FnAcnPa = \"Sc bvevkyA r eTIbUFGBm ipting vECZKbl Usw ile pCDSksBatLwvCj System Sp yAcXJ Obj wijIuS ect wfJDtNj\".split(\" " ascii
    $s6  = "WKeIW.open(uHAEl,jExSi,false);" fullword ascii
    $s7  = "function DqKluaf(ADPq) {" fullword ascii
    $s8  = "return ZC.ExpandEnvironmentStrings(bDHfZ[6]);" fullword ascii
    $s9  = "return YjVZ.responseBody;" fullword ascii
    $s10 = "function weLa(sfFTh) {" fullword ascii
    $s11 = "if (((new Date())>0,7672868888)) {" fullword ascii
    $s12 = "function CXBKxLMDH(WDnDKSYPBUN) {" fullword ascii
    $s13 = "return CrSmaBa" fullword ascii
    $s14 = "function iVenicx(YjVZ) {" fullword ascii
    $s15 = "if(o>=I.length) {break;}" fullword ascii
    $s16 = "function pGsEERTr() {" fullword ascii
    $s17 = "function XHHl(PHncl) {" fullword ascii
    $s18 = "function Sfha(fIcjR) {" fullword ascii
    $s19 = "return new ActiveXObject(RwgOTb);" fullword ascii
    $s20 = "function JZPY(HSVQF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}