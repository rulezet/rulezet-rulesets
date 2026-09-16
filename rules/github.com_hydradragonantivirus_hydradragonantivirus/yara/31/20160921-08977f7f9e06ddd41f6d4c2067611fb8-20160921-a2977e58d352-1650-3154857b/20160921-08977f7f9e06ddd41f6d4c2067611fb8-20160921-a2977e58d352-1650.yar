rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_a2977e58d352_1650 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash3       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1  = " \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s2  = "nction f000(){return \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s3  = "ction f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s4  = "eturn \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5  = "){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";}" ascii
    $s6  = "unction f000(){return \"Mt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii
    $s7  = " f000(){return \"YTp\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s8  = "n f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"W" ascii
    $s9  = "a\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s10 = ";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f0" ascii
    $s11 = "urn \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}