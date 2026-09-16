rule TTP_XOR_QUAD_CurrentVersionRun_66a8 {
  strings:
    $key_66a8 = { 35 c7 [2] 11 c9 [2] 3a e5 [2] 14 c7 [2] 00 dc [2] 0f c6 [2] 11 db [2] 13 da [2] 08 dc [2] 14 db [2] 08 f4 }

  condition:
    any of them
}