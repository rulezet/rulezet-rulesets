rule TTP_XOR_QUAD_CurrentVersionRun_66a9 {
  strings:
    $key_66a9 = { 35 c6 [2] 11 c8 [2] 3a e4 [2] 14 c6 [2] 00 dd [2] 0f c7 [2] 11 da [2] 13 db [2] 08 dd [2] 14 da [2] 08 f5 }

  condition:
    any of them
}