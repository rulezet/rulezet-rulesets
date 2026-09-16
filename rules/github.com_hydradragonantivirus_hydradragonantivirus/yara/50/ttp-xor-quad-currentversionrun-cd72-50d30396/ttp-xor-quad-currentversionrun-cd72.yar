rule TTP_XOR_QUAD_CurrentVersionRun_cd72 {
  strings:
    $key_cd72 = { 9e 1d [2] ba 13 [2] 91 3f [2] bf 1d [2] ab 06 [2] a4 1c [2] ba 01 [2] b8 00 [2] a3 06 [2] bf 01 [2] a3 2e }

  condition:
    any of them
}