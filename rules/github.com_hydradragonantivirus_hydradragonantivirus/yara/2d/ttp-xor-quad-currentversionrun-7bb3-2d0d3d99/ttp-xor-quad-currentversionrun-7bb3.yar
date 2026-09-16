rule TTP_XOR_QUAD_CurrentVersionRun_7bb3 {
  strings:
    $key_7bb3 = { 28 dc [2] 0c d2 [2] 27 fe [2] 09 dc [2] 1d c7 [2] 12 dd [2] 0c c0 [2] 0e c1 [2] 15 c7 [2] 09 c0 [2] 15 ef }

  condition:
    any of them
}