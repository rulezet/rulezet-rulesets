rule TTP_XOR_QUAD_CurrentVersionRun_1fa8 {
  strings:
    $key_1fa8 = { 4c c7 [2] 68 c9 [2] 43 e5 [2] 6d c7 [2] 79 dc [2] 76 c6 [2] 68 db [2] 6a da [2] 71 dc [2] 6d db [2] 71 f4 }

  condition:
    any of them
}