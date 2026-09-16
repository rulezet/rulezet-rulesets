rule TTP_XOR_QUAD_CurrentVersionRun_c4a8 {
  strings:
    $key_c4a8 = { 97 c7 [2] b3 c9 [2] 98 e5 [2] b6 c7 [2] a2 dc [2] ad c6 [2] b3 db [2] b1 da [2] aa dc [2] b6 db [2] aa f4 }

  condition:
    any of them
}