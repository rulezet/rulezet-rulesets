rule _20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1_20160921_d999dcba53f5_4011 {
  meta:
    description = "datamaliciousorder - from files 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s2 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(function f000(){return " ascii
    $s3 = "),(function f000(){return \"IPu\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s4 = "n f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s5 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Km\";})(),(function f000" ascii
    $s6 = "eturn \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Tn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}