rule TTP_XOR_QUAD_CurrentVersionRun_cfb8 {
  strings:
    $key_cfb8 = { 9c d7 [2] b8 d9 [2] 93 f5 [2] bd d7 [2] a9 cc [2] a6 d6 [2] b8 cb [2] ba ca [2] a1 cc [2] bd cb [2] a1 e4 }

  condition:
    any of them
}