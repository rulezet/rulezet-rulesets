rule TTP_XOR_QUAD_CurrentVersionRun_c5a6 {
  strings:
    $key_c5a6 = { 96 c9 [2] b2 c7 [2] 99 eb [2] b7 c9 [2] a3 d2 [2] ac c8 [2] b2 d5 [2] b0 d4 [2] ab d2 [2] b7 d5 [2] ab fa }

  condition:
    any of them
}