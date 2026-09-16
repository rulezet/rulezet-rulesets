rule _20160921_ba8a9f239804499b5d1d2a06a862c1ca_20160921_d4f0c091f748_5659 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash2       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "turn \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})()," ascii
    $s2 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii
    $s3 = " \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s4 = "GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(functio" ascii
    $s5 = "n f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}