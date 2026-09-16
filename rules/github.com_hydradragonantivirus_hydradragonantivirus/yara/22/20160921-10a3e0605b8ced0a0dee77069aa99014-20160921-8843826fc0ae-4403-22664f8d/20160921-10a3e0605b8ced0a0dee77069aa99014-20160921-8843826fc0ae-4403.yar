rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_8843826fc0ae_4403 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_8843826fc0ae466921b7811b54d8314e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";}" ascii
    $s2 = "DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s3 = "WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s4 = " f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp" ascii
    $s5 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}