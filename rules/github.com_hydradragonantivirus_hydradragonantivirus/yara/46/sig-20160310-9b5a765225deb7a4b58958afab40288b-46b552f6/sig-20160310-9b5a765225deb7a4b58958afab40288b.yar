rule sig_20160310_9b5a765225deb7a4b58958afab40288b {
  meta:
    description = "datamaliciousorder - file 20160310_9b5a765225deb7a4b58958afab40288b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b49bb5701c7929768c921e63492686c12cc614c1a508d88c55049b84edfd4c"

  strings:
    $s1  = "return wGYeYcf[0] + wGYeYcf[2] + wGYeYcf[4] + \".F\" + wGYeYcf[7] + wGYeYcf[9] + wGYeYcf[12] + wGYeYcf[14];" fullword ascii
    $s2  = "var DL = true  , PTFb = OvH[7] + OvH[9] + OvH[11];" fullword ascii
    $s3  = "TJOhL.open(fyziu,BDwjI,false);" fullword ascii
    $s4  = "var wGYeYcf = \"Sc ZQpaVXz r zeQPCXpzd ipting ewLVATH edO ile vAGyOMICrOdTmI System Fe xAYUb Obj QElYaG ect WWMYHfO\".split(\" " ascii
    $s5  = "mEg = Q; break; " fullword ascii
    $s6  = "function QdeF(TJOhL,BDwjI,fyziu) {" fullword ascii
    $s7  = "return new ActiveXObject(BFDePP);" fullword ascii
    $s8  = "return kgP.size;" fullword ascii
    $s9  = "if (NyziK == 1168-968){return true;} else {return false;}" fullword ascii
    $s10 = "return xoUAAIm" fullword ascii
    $s11 = "function JTIA(UGseB) {" fullword ascii
    $s12 = "function rMLv(aTiQh) {" fullword ascii
    $s13 = "return GGoCn.status;" fullword ascii
    $s14 = "function ohkf(OVpIO,VuePS) {" fullword ascii
    $s15 = "if (v >= WlxHv.length) {break;}" fullword ascii
    $s16 = "function gkOBnvPV(OnXdS,eLYTHe) {" fullword ascii
    $s17 = "function IXQpFZuq(kgP) {" fullword ascii
    $s18 = "function siEmM(BFDePP) {" fullword ascii
    $s19 = "if(Q>=y.length) {break;}" fullword ascii
    $s20 = "function GPPV(WlxHv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}