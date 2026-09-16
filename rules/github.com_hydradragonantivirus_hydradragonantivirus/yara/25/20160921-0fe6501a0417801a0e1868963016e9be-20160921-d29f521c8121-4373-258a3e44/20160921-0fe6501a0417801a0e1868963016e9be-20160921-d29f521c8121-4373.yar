rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_d29f521c8121_4373 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"

  strings:
    $s1 = " f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SG" ascii
    $s2 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})()," ascii
    $s3 = "n \"HJm\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = "n \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s5 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"K" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}