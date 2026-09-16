rule _20160921_68e1fc90afca497654d8f771197c2097_20160922_433c067ed379_5340 {
  meta:
    description = "datamaliciousorder - from files 20160921_68e1fc90afca497654d8f771197c2097.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash2       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash3       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "eturn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})()" ascii
    $s2 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s3 = "n f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"" ascii
    $s4 = "(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"PTs\";" ascii
    $s5 = "000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DN" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}