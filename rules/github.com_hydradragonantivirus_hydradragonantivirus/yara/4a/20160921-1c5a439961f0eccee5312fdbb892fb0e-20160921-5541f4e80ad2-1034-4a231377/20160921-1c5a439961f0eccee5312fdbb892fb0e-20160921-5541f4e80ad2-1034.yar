rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_5541f4e80ad2_1034 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"

  strings:
    $s1  = "Mj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(functio" ascii
    $s2  = "000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQ" ascii
    $s3  = "tion f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s4  = "turn \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5  = "(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})" ascii
    $s6  = "rn \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s7  = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f" ascii
    $s8  = "){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";}" ascii
    $s9  = "eturn \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s10 = "on f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s11 = "ction f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){retur" ascii
    $s12 = "unction f000(){return \"Ut\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s13 = "function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MMz\";})(),(function f000(){r" ascii
    $s14 = "){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})" ascii
    $s15 = "j\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function" ascii
    $s16 = "(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\"" ascii
    $s17 = "function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s18 = "f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}