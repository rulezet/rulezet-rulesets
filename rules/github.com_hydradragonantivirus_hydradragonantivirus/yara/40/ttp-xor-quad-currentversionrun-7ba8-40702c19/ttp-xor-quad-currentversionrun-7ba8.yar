rule TTP_XOR_QUAD_CurrentVersionRun_7ba8 {
  strings:
    $key_7ba8 = { 28 c7 [2] 0c c9 [2] 27 e5 [2] 09 c7 [2] 1d dc [2] 12 c6 [2] 0c db [2] 0e da [2] 15 dc [2] 09 db [2] 15 f4 }

  condition:
    any of them
}