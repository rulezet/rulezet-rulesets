rule TTP_XOR_QUAD_CurrentVersionRun_d7a6 {
  strings:
    $key_d7a6 = { 84 c9 [2] a0 c7 [2] 8b eb [2] a5 c9 [2] b1 d2 [2] be c8 [2] a0 d5 [2] a2 d4 [2] b9 d2 [2] a5 d5 [2] b9 fa }

  condition:
    any of them
}