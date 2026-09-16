rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_d999dcba53f5_648 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe" ascii
    $s2  = "n f000(){return \"RLk\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"" ascii
    $s3  = "GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s4  = "urn \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s5  = ")(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s6  = "0(){return \"IPu\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\"" ascii
    $s7  = "\"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Br\";})(),(functio" ascii
    $s8  = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"EZu\";})(),(function f000(){re" ascii
    $s9  = "urn \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s10 = "n \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s11 = "(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s12 = "00(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s13 = "n f000(){return \"Uo\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"M" ascii
    $s14 = "(){return \"RLk\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";" ascii
    $s15 = " f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br" ascii
    $s16 = "on f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return " ascii
    $s17 = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s18 = "turn \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s19 = "turn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"HJm\";})(),(" ascii
    $s20 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}