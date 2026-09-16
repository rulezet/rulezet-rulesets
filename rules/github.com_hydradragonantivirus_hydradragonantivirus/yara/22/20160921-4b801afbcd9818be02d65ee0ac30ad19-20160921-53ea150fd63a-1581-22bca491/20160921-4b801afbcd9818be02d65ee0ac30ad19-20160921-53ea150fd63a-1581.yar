rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_53ea150fd63a_1581 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_53ea150fd63a4ef657412c858a71a13e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"

  strings:
    $s1  = "(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";}" ascii
    $s2  = "f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s3  = "){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})" ascii
    $s4  = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(" ascii
    $s5  = "eturn \"IAa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})()" ascii
    $s6  = "tion f000(){return \"DAp\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s7  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s8  = " f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"U" ascii
    $s9  = "\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s10 = "nction f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"HJm\";})(),(function f000(){ret" ascii
    $s11 = "turn \"BQb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s12 = "urn \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sq\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}