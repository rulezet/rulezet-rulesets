rule TTP_XOR_QUAD_CurrentVersionRun_27a8 {
  strings:
    $key_27a8 = { 74 c7 [2] 50 c9 [2] 7b e5 [2] 55 c7 [2] 41 dc [2] 4e c6 [2] 50 db [2] 52 da [2] 49 dc [2] 55 db [2] 49 f4 }

  condition:
    any of them
}