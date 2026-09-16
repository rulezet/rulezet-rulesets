rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_daba59e7a6b9_5283 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return" ascii
    $s2 = "tion f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s3 = "eturn \"HJm\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(" ascii
    $s4 = "eturn \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})()" ascii
    $s5 = ";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}