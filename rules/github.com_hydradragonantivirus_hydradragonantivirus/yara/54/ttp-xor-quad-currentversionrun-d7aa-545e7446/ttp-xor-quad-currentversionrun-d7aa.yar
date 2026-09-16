rule TTP_XOR_QUAD_CurrentVersionRun_d7aa {
  strings:
    $key_d7aa = { 84 c5 [2] a0 cb [2] 8b e7 [2] a5 c5 [2] b1 de [2] be c4 [2] a0 d9 [2] a2 d8 [2] b9 de [2] a5 d9 [2] b9 f6 }

  condition:
    any of them
}