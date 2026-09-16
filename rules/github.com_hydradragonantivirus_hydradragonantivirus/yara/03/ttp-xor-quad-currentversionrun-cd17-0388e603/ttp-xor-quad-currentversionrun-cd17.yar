rule TTP_XOR_QUAD_CurrentVersionRun_cd17 {
  strings:
    $key_cd17 = { 9e 78 [2] ba 76 [2] 91 5a [2] bf 78 [2] ab 63 [2] a4 79 [2] ba 64 [2] b8 65 [2] a3 63 [2] bf 64 [2] a3 4b }

  condition:
    any of them
}