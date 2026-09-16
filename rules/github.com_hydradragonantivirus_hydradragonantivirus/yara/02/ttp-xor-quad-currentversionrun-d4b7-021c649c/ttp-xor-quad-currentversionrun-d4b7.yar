rule TTP_XOR_QUAD_CurrentVersionRun_d4b7 {
  strings:
    $key_d4b7 = { 87 d8 [2] a3 d6 [2] 88 fa [2] a6 d8 [2] b2 c3 [2] bd d9 [2] a3 c4 [2] a1 c5 [2] ba c3 [2] a6 c4 [2] ba eb }

  condition:
    any of them
}