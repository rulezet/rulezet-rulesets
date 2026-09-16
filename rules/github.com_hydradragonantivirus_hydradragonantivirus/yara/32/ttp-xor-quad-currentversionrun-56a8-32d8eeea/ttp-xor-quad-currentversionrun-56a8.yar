rule TTP_XOR_QUAD_CurrentVersionRun_56a8 {
  strings:
    $key_56a8 = { 05 c7 [2] 21 c9 [2] 0a e5 [2] 24 c7 [2] 30 dc [2] 3f c6 [2] 21 db [2] 23 da [2] 38 dc [2] 24 db [2] 38 f4 }

  condition:
    any of them
}