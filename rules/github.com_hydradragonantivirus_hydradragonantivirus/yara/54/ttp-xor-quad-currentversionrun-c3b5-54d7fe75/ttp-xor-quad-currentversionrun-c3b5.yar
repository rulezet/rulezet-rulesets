rule TTP_XOR_QUAD_CurrentVersionRun_c3b5 {
  strings:
    $key_c3b5 = { 90 da [2] b4 d4 [2] 9f f8 [2] b1 da [2] a5 c1 [2] aa db [2] b4 c6 [2] b6 c7 [2] ad c1 [2] b1 c6 [2] ad e9 }

  condition:
    any of them
}