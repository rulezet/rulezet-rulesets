rule TTP_XOR_QUAD_CurrentVersionRun_c297 {
  strings:
    $key_c297 = { 91 f8 [2] b5 f6 [2] 9e da [2] b0 f8 [2] a4 e3 [2] ab f9 [2] b5 e4 [2] b7 e5 [2] ac e3 [2] b0 e4 [2] ac cb }

  condition:
    any of them
}