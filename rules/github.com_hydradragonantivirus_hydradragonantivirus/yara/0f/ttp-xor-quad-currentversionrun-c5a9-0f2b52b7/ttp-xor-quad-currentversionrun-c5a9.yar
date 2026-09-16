rule TTP_XOR_QUAD_CurrentVersionRun_c5a9 {
  strings:
    $key_c5a9 = { 96 c6 [2] b2 c8 [2] 99 e4 [2] b7 c6 [2] a3 dd [2] ac c7 [2] b2 da [2] b0 db [2] ab dd [2] b7 da [2] ab f5 }

  condition:
    any of them
}