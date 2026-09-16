rule TTP_XOR_QUAD_CurrentVersionRun_5ba8 {
  strings:
    $key_5ba8 = { 08 c7 [2] 2c c9 [2] 07 e5 [2] 29 c7 [2] 3d dc [2] 32 c6 [2] 2c db [2] 2e da [2] 35 dc [2] 29 db [2] 35 f4 }

  condition:
    any of them
}