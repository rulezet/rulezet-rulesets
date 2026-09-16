rule _20160921_68e1fc90afca497654d8f771197c2097_20160921_daba59e7a6b9_5339 {
  meta:
    description = "datamaliciousorder - from files 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = "v\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s2 = "urn \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3 = "f000(){return \"DNa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"W" ascii
    $s4 = "){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";" ascii
    $s5 = "a\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}