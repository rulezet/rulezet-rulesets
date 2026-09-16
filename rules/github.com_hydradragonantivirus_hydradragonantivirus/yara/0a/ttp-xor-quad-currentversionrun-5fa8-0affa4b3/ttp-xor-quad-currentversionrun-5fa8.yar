rule TTP_XOR_QUAD_CurrentVersionRun_5fa8 {
  strings:
    $key_5fa8 = { 0c c7 [2] 28 c9 [2] 03 e5 [2] 2d c7 [2] 39 dc [2] 36 c6 [2] 28 db [2] 2a da [2] 31 dc [2] 2d db [2] 31 f4 }

  condition:
    any of them
}