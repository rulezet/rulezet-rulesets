rule TTP_XOR_QUAD_CurrentVersionRun_c3a8 {
  strings:
    $key_c3a8 = { 90 c7 [2] b4 c9 [2] 9f e5 [2] b1 c7 [2] a5 dc [2] aa c6 [2] b4 db [2] b6 da [2] ad dc [2] b1 db [2] ad f4 }

  condition:
    any of them
}