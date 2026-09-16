rule TTP_XOR_QUAD_CurrentVersionRun_c1a9 {
  strings:
    $key_c1a9 = { 92 c6 [2] b6 c8 [2] 9d e4 [2] b3 c6 [2] a7 dd [2] a8 c7 [2] b6 da [2] b4 db [2] af dd [2] b3 da [2] af f5 }

  condition:
    any of them
}