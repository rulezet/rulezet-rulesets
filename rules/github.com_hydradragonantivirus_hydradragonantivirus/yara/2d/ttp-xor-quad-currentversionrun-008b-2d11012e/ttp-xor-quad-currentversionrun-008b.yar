rule TTP_XOR_QUAD_CurrentVersionRun_008b {
  strings:
    $key_008b = { 53 e4 [2] 77 ea [2] 5c c6 [2] 72 e4 [2] 66 ff [2] 69 e5 [2] 77 f8 [2] 75 f9 [2] 6e ff [2] 72 f8 [2] 6e d7 }

  condition:
    any of them
}