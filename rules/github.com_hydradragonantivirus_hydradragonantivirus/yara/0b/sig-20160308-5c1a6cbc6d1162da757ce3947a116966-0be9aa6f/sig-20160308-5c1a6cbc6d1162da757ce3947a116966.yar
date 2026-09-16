rule sig_20160308_5c1a6cbc6d1162da757ce3947a116966 {
  meta:
    description = "datamaliciousorder - file 20160308_5c1a6cbc6d1162da757ce3947a116966.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aebeafb62a300bc63ab65abbf4a75f9218ae08bcf2c871253184a8f9669bc150"

  strings:
    $s1  = "return HGxFaFV[0] + HGxFaFV[2] + HGxFaFV[4] + \".F\" + HGxFaFV[7] + HGxFaFV[9] + HGxFaFV[12] + HGxFaFV[14];" fullword ascii
    $s2  = "var pP = true  , VNag = fvf[7] + fvf[9] + fvf[11];" fullword ascii
    $s3  = "var fvf = (\"2.XMLHTTP VNYjfUQ VueOD XML ream St GOYVBVIy AD iphCFTs O XpMz D\").split(\" \");" fullword ascii
    $s4  = "var HGxFaFV = \"Sc zzlTUNq r OuTryeKxe ipting RuJWjiu tcQ ile VTGNyqpSjueGdC System zx PBesI Obj vVBKpQ ect Kevdsst\".split(\" " ascii
    $s5  = "IdOjd.open(mEbra,IkYKo,false);" fullword ascii
    $s6  = "if (eGdlP > 199672-341){return true;} else {return false;}" fullword ascii
    $s7  = "function iKie(iRfEq) {" fullword ascii
    $s8  = "function fLtU(kvSwc) {" fullword ascii
    $s9  = "function DDFQBeHC(hbV) {" fullword ascii
    $s10 = "if(o>=L.length) {break;}" fullword ascii
    $s11 = "function kBaj(DdVly,nCBqr) {" fullword ascii
    $s12 = "function INhtWRPgv(oryzuFhNvRl) {" fullword ascii
    $s13 = "return iffqsWy" fullword ascii
    $s14 = "function dqrj(cwbFN) {" fullword ascii
    $s15 = "function jIlNbqL(IXMH) {" fullword ascii
    $s16 = "return gMVFG;" fullword ascii
    $s17 = "return xJpX.responseBody;" fullword ascii
    $s18 = "function FNGnp(Lwxwvf) {" fullword ascii
    $s19 = "return new ActiveXObject(Lwxwvf);" fullword ascii
    $s20 = "function SYQH(IdOjd,IkYKo,mEbra) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}