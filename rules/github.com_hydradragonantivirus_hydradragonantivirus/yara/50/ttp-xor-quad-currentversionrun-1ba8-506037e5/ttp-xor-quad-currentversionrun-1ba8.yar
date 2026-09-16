rule TTP_XOR_QUAD_CurrentVersionRun_1ba8 {
  strings:
    $key_1ba8 = { 48 c7 [2] 6c c9 [2] 47 e5 [2] 69 c7 [2] 7d dc [2] 72 c6 [2] 6c db [2] 6e da [2] 75 dc [2] 69 db [2] 75 f4 }

  condition:
    any of them
}