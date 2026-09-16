rule TTP_XOR_QUAD_CurrentVersionRun_54a8 {
  strings:
    $key_54a8 = { 07 c7 [2] 23 c9 [2] 08 e5 [2] 26 c7 [2] 32 dc [2] 3d c6 [2] 23 db [2] 21 da [2] 3a dc [2] 26 db [2] 3a f4 }

  condition:
    any of them
}