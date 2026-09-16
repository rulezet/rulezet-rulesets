rule TTP_XOR_QUAD_CurrentVersionRun_7fa8 {
  strings:
    $key_7fa8 = { 2c c7 [2] 08 c9 [2] 23 e5 [2] 0d c7 [2] 19 dc [2] 16 c6 [2] 08 db [2] 0a da [2] 11 dc [2] 0d db [2] 11 f4 }

  condition:
    any of them
}