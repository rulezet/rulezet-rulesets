rule TTP_XOR_QUAD_CurrentVersionRun_56a9 {
  strings:
    $key_56a9 = { 05 c6 [2] 21 c8 [2] 0a e4 [2] 24 c6 [2] 30 dd [2] 3f c7 [2] 21 da [2] 23 db [2] 38 dd [2] 24 da [2] 38 f5 }

  condition:
    any of them
}