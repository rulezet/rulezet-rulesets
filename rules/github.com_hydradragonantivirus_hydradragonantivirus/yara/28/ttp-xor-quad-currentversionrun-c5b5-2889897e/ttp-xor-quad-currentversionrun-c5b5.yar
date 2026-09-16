rule TTP_XOR_QUAD_CurrentVersionRun_c5b5 {
  strings:
    $key_c5b5 = { 96 da [2] b2 d4 [2] 99 f8 [2] b7 da [2] a3 c1 [2] ac db [2] b2 c6 [2] b0 c7 [2] ab c1 [2] b7 c6 [2] ab e9 }

  condition:
    any of them
}