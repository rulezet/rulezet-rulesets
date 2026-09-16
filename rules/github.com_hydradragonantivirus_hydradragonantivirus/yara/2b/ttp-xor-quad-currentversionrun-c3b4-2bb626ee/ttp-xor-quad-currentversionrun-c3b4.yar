rule TTP_XOR_QUAD_CurrentVersionRun_c3b4 {
  strings:
    $key_c3b4 = { 90 db [2] b4 d5 [2] 9f f9 [2] b1 db [2] a5 c0 [2] aa da [2] b4 c7 [2] b6 c6 [2] ad c0 [2] b1 c7 [2] ad e8 }

  condition:
    any of them
}