rule TTP_XOR_QUAD_CurrentVersionRun_57a8 {
  strings:
    $key_57a8 = { 04 c7 [2] 20 c9 [2] 0b e5 [2] 25 c7 [2] 31 dc [2] 3e c6 [2] 20 db [2] 22 da [2] 39 dc [2] 25 db [2] 39 f4 }

  condition:
    any of them
}