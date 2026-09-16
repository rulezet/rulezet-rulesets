rule _20160921_60c26fdfafa2666b92246aea46e32175_20160922_b9c8ae1e2648_5292 {
  meta:
    description = "datamaliciousorder - from files 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash2       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\"" ascii
    $s2 = " \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(func" ascii
    $s3 = "0(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";" ascii
    $s4 = "urn \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s5 = "Gn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}