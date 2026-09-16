rule TTP_XOR_QUAD_CurrentVersionRun_cd2b {
  strings:
    $key_cd2b = { 9e 44 [2] ba 4a [2] 91 66 [2] bf 44 [2] ab 5f [2] a4 45 [2] ba 58 [2] b8 59 [2] a3 5f [2] bf 58 [2] a3 77 }

  condition:
    any of them
}