rule TTP_XOR_QUAD_CurrentVersionRun_408b {
  strings:
    $key_408b = { 13 e4 [2] 37 ea [2] 1c c6 [2] 32 e4 [2] 26 ff [2] 29 e5 [2] 37 f8 [2] 35 f9 [2] 2e ff [2] 32 f8 [2] 2e d7 }

  condition:
    any of them
}