rule _20160921_60c26fdfafa2666b92246aea46e32175_20160921_a39f22c0c39a_5293 {
  meta:
    description = "datamaliciousorder - from files 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash2       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1 = "on f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s2 = "\"BQb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s3 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"BQb\";})" ascii
    $s4 = " f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"U" ascii
    $s5 = "rn \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}