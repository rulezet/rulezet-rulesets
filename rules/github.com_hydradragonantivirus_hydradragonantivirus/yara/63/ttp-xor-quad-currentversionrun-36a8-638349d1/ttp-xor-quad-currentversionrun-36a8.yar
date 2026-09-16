rule TTP_XOR_QUAD_CurrentVersionRun_36a8 {
  strings:
    $key_36a8 = { 65 c7 [2] 41 c9 [2] 6a e5 [2] 44 c7 [2] 50 dc [2] 5f c6 [2] 41 db [2] 43 da [2] 58 dc [2] 44 db [2] 58 f4 }

  condition:
    any of them
}