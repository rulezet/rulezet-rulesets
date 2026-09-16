rule TTP_XOR_QUAD_CurrentVersionRun_4ba8 {
  strings:
    $key_4ba8 = { 18 c7 [2] 3c c9 [2] 17 e5 [2] 39 c7 [2] 2d dc [2] 22 c6 [2] 3c db [2] 3e da [2] 25 dc [2] 39 db [2] 25 f4 }

  condition:
    any of them
}