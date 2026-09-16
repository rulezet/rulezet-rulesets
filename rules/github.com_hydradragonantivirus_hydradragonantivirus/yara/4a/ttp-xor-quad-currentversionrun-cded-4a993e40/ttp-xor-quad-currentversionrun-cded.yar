rule TTP_XOR_QUAD_CurrentVersionRun_cded {
  strings:
    $key_cded = { 9e 82 [2] ba 8c [2] 91 a0 [2] bf 82 [2] ab 99 [2] a4 83 [2] ba 9e [2] b8 9f [2] a3 99 [2] bf 9e [2] a3 b1 }

  condition:
    any of them
}