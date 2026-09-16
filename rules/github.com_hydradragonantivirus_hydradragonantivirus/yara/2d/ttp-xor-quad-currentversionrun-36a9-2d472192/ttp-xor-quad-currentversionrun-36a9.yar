rule TTP_XOR_QUAD_CurrentVersionRun_36a9 {
  strings:
    $key_36a9 = { 65 c6 [2] 41 c8 [2] 6a e4 [2] 44 c6 [2] 50 dd [2] 5f c7 [2] 41 da [2] 43 db [2] 58 dd [2] 44 da [2] 58 f5 }

  condition:
    any of them
}