rule TTP_XOR_QUAD_CurrentVersionRun_67a8 {
  strings:
    $key_67a8 = { 34 c7 [2] 10 c9 [2] 3b e5 [2] 15 c7 [2] 01 dc [2] 0e c6 [2] 10 db [2] 12 da [2] 09 dc [2] 15 db [2] 09 f4 }

  condition:
    any of them
}