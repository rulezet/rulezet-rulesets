rule TTP_XOR_QUAD_CurrentVersionRun_708d {
  strings:
    $key_708d = { 23 e2 [2] 07 ec [2] 2c c0 [2] 02 e2 [2] 16 f9 [2] 19 e3 [2] 07 fe [2] 05 ff [2] 1e f9 [2] 02 fe [2] 1e d1 }

  condition:
    any of them
}