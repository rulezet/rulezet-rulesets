rule TTP_XOR_QUAD_CurrentVersionRun_c5a8 {
  strings:
    $key_c5a8 = { 96 c7 [2] b2 c9 [2] 99 e5 [2] b7 c7 [2] a3 dc [2] ac c6 [2] b2 db [2] b0 da [2] ab dc [2] b7 db [2] ab f4 }

  condition:
    any of them
}