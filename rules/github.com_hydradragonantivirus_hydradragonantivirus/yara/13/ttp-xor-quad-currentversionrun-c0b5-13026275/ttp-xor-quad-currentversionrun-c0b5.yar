rule TTP_XOR_QUAD_CurrentVersionRun_c0b5 {
  strings:
    $key_c0b5 = { 93 da [2] b7 d4 [2] 9c f8 [2] b2 da [2] a6 c1 [2] a9 db [2] b7 c6 [2] b5 c7 [2] ae c1 [2] b2 c6 [2] ae e9 }

  condition:
    any of them
}