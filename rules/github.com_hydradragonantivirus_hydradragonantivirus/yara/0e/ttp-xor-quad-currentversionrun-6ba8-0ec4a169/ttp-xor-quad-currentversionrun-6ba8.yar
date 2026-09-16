rule TTP_XOR_QUAD_CurrentVersionRun_6ba8 {
  strings:
    $key_6ba8 = { 38 c7 [2] 1c c9 [2] 37 e5 [2] 19 c7 [2] 0d dc [2] 02 c6 [2] 1c db [2] 1e da [2] 05 dc [2] 19 db [2] 05 f4 }

  condition:
    any of them
}