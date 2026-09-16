rule _20160921_02b826231ece268e91633311d2c70554_20160921_18f3e0383dae_1526 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_18f3e0383dae972ccd3326bfeb339081.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"

  strings:
    $s1  = "n f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii
    $s2  = "(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Km\";})" ascii
    $s3  = "eturn \"Yv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})()," ascii
    $s4  = "})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s5  = "){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";}" ascii
    $s6  = "tion f000(){return \"NBs\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s7  = "000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"RPt" ascii
    $s8  = "ction f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){retur" ascii
    $s9  = ";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BQb\";})(),(function f0" ascii
    $s10 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"PTs\";})" ascii
    $s11 = "(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(){r" ascii
    $s12 = "\"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}