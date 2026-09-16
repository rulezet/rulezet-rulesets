rule TTP_XOR_QUAD_CurrentVersionRun_c7a6 {
  strings:
    $key_c7a6 = { 94 c9 [2] b0 c7 [2] 9b eb [2] b5 c9 [2] a1 d2 [2] ae c8 [2] b0 d5 [2] b2 d4 [2] a9 d2 [2] b5 d5 [2] a9 fa }

  condition:
    any of them
}