rule TTP_XOR_QUAD_CurrentVersionRun_cd1b {
  strings:
    $key_cd1b = { 9e 74 [2] ba 7a [2] 91 56 [2] bf 74 [2] ab 6f [2] a4 75 [2] ba 68 [2] b8 69 [2] a3 6f [2] bf 68 [2] a3 47 }

  condition:
    any of them
}