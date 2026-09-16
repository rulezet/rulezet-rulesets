rule _20160921_68e1fc90afca497654d8f771197c2097_20160921_8b27f7688489_1499 {
  meta:
    description = "datamaliciousorder - from files 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1  = "),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(function f000(){" ascii
    $s2  = "urn \"YTp\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s3  = "on f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s4  = "n f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s5  = "on f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"" ascii
    $s6  = " \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(func" ascii
    $s7  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000" ascii
    $s8  = "nction f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){retu" ascii
    $s9  = "n f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"" ascii
    $s10 = "(),(function f000(){return \"BMj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s11 = "ction f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s12 = ")(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s13 = "eturn \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}