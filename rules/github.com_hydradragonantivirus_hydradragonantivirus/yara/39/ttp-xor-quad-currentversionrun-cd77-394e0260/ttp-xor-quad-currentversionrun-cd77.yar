rule TTP_XOR_QUAD_CurrentVersionRun_cd77 {
  strings:
    $key_cd77 = { 9e 18 [2] ba 16 [2] 91 3a [2] bf 18 [2] ab 03 [2] a4 19 [2] ba 04 [2] b8 05 [2] a3 03 [2] bf 04 [2] a3 2b }

  condition:
    any of them
}