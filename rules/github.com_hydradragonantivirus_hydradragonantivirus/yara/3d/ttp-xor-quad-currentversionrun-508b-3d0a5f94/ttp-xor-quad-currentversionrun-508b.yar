rule TTP_XOR_QUAD_CurrentVersionRun_508b {
  strings:
    $key_508b = { 03 e4 [2] 27 ea [2] 0c c6 [2] 22 e4 [2] 36 ff [2] 39 e5 [2] 27 f8 [2] 25 f9 [2] 3e ff [2] 22 f8 [2] 3e d7 }

  condition:
    any of them
}