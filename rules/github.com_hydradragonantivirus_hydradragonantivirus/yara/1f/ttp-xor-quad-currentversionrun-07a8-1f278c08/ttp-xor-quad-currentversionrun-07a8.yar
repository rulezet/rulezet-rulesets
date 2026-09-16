rule TTP_XOR_QUAD_CurrentVersionRun_07a8 {
  strings:
    $key_07a8 = { 54 c7 [2] 70 c9 [2] 5b e5 [2] 75 c7 [2] 61 dc [2] 6e c6 [2] 70 db [2] 72 da [2] 69 dc [2] 75 db [2] 69 f4 }

  condition:
    any of them
}