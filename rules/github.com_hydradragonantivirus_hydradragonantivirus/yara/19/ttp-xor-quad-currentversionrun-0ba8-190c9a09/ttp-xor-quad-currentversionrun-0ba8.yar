rule TTP_XOR_QUAD_CurrentVersionRun_0ba8 {
  strings:
    $key_0ba8 = { 58 c7 [2] 7c c9 [2] 57 e5 [2] 79 c7 [2] 6d dc [2] 62 c6 [2] 7c db [2] 7e da [2] 65 dc [2] 79 db [2] 65 f4 }

  condition:
    any of them
}