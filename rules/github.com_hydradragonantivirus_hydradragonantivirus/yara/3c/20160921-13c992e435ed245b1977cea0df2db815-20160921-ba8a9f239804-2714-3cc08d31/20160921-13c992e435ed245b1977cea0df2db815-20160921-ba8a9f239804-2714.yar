rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_ba8a9f239804_2714 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = ")(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s2 = "){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){retu" ascii
    $s4 = "n \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(f" ascii
    $s5 = "0(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s6 = "eturn \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s7 = "),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}