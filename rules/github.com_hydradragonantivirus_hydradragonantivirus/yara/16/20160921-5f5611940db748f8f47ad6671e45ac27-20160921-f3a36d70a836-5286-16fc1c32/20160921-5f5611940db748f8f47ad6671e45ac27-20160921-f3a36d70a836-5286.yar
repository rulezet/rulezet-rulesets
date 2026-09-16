rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_f3a36d70a836_5286 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = " \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s2 = "){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(" ascii
    $s3 = "urn \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s4 = "eturn \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})()" ascii
    $s5 = " f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GG" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}