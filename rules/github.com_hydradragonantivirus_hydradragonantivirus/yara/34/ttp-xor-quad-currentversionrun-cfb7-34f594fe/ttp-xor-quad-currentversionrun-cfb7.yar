rule TTP_XOR_QUAD_CurrentVersionRun_cfb7 {
  strings:
    $key_cfb7 = { 9c d8 [2] b8 d6 [2] 93 fa [2] bd d8 [2] a9 c3 [2] a6 d9 [2] b8 c4 [2] ba c5 [2] a1 c3 [2] bd c4 [2] a1 eb }

  condition:
    any of them
}