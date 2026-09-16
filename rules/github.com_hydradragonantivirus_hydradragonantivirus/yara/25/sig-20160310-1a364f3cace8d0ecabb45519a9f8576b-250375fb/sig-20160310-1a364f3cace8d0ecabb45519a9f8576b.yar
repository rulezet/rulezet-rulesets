rule sig_20160310_1a364f3cace8d0ecabb45519a9f8576b {
  meta:
    description = "datamaliciousorder - file 20160310_1a364f3cace8d0ecabb45519a9f8576b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f1ccd1d3db099142657e1fa6f7fbe119b3d525906e9dd47a9f2bc1be22a2156"

  strings:
    $s1  = "return PxMJrCZ[0] + PxMJrCZ[2] + PxMJrCZ[4] + \".F\" + PxMJrCZ[7] + PxMJrCZ[9] + PxMJrCZ[12] + PxMJrCZ[14];" fullword ascii
    $s2  = "var fk = true  , zGKj = tFX[7] + tFX[9] + tFX[11];" fullword ascii
    $s3  = "var tFX = (\"2.XMLHTTP zGBNcEi YdnSk XML ream St rqNVNIfq AD TNLzYqP O BAJo D\").split(\" \");" fullword ascii
    $s4  = "YmcNG.open(Ssisg,nBjpP,false);" fullword ascii
    $s5  = "var PxMJrCZ = \"Sc kqICTsN r RZWuihFGN ipting Wfkxqxz Mlx ile ipucqpgpufSLNy System ms aWxJZ Obj BKzKGB ect TaMOIbn\".split(\" " ascii
    $s6  = "return LXFtbj.position=702-702;" fullword ascii
    $s7  = "return FLgve.status;" fullword ascii
    $s8  = "return hJwR.ExpandEnvironmentStrings(bJdkv);" fullword ascii
    $s9  = "function SwQJA(KFzzDn) {" fullword ascii
    $s10 = "return Rkx.size;" fullword ascii
    $s11 = "function RLhI(baafk) {" fullword ascii
    $s12 = "function WcGHmxse(Rkx) {" fullword ascii
    $s13 = "return VGhea;" fullword ascii
    $s14 = "Zts = J; break; " fullword ascii
    $s15 = "function OgZFYfLi(wLKkF,OyeMbY) {" fullword ascii
    $s16 = "return OPACoQy" fullword ascii
    $s17 = "function PvUL(vJVud,VzcTg) {" fullword ascii
    $s18 = "if (EdPVM > 152256-594){return true;} else {return false;}" fullword ascii
    $s19 = "function wdXLYNMr() {" fullword ascii
    $s20 = "function eEsS(EdPVM) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}