rule _20160921_e949fdc198fee477717395093f5853e7_20160921_e985c90f8141_1752 {
  meta:
    description = "datamaliciousorder - from files 20160921_e949fdc198fee477717395093f5853e7.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash2       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1  = "urn \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(" ascii
    $s2  = "\"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s3  = " f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"P" ascii
    $s4  = "{return \"BQb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})" ascii
    $s5  = "(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){r" ascii
    $s6  = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"HJm\"" ascii
    $s7  = "\"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(func" ascii
    $s8  = "unction f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s9  = "(),(function f000(){return \"DNa\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s10 = "n \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s11 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yv\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}