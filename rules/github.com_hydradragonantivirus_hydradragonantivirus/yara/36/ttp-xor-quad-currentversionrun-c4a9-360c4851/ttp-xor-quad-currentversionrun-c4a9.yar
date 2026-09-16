rule TTP_XOR_QUAD_CurrentVersionRun_c4a9 {
  strings:
    $key_c4a9 = { 97 c6 [2] b3 c8 [2] 98 e4 [2] b6 c6 [2] a2 dd [2] ad c7 [2] b3 da [2] b1 db [2] aa dd [2] b6 da [2] aa f5 }

  condition:
    any of them
}