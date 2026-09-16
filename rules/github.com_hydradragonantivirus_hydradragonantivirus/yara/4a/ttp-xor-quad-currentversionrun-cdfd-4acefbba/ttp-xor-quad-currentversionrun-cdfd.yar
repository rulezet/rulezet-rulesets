rule TTP_XOR_QUAD_CurrentVersionRun_cdfd {
  strings:
    $key_cdfd = { 9e 92 [2] ba 9c [2] 91 b0 [2] bf 92 [2] ab 89 [2] a4 93 [2] ba 8e [2] b8 8f [2] a3 89 [2] bf 8e [2] a3 a1 }

  condition:
    any of them
}