rule TTP_XOR_QUAD_CurrentVersionRun_d7a9 {
  strings:
    $key_d7a9 = { 84 c6 [2] a0 c8 [2] 8b e4 [2] a5 c6 [2] b1 dd [2] be c7 [2] a0 da [2] a2 db [2] b9 dd [2] a5 da [2] b9 f5 }

  condition:
    any of them
}