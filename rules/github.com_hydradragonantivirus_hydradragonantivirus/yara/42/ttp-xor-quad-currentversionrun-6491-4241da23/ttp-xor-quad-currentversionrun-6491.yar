rule TTP_XOR_QUAD_CurrentVersionRun_6491 {
  strings:
    $key_6491 = { 37 fe [2] 13 f0 [2] 38 dc [2] 16 fe [2] 02 e5 [2] 0d ff [2] 13 e2 [2] 11 e3 [2] 0a e5 [2] 16 e2 [2] 0a cd }

  condition:
    any of them
}