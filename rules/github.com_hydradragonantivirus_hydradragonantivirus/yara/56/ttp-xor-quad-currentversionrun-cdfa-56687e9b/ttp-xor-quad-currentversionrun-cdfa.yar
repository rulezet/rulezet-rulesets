rule TTP_XOR_QUAD_CurrentVersionRun_cdfa {
  strings:
    $key_cdfa = { 9e 95 [2] ba 9b [2] 91 b7 [2] bf 95 [2] ab 8e [2] a4 94 [2] ba 89 [2] b8 88 [2] a3 8e [2] bf 89 [2] a3 a6 }

  condition:
    any of them
}