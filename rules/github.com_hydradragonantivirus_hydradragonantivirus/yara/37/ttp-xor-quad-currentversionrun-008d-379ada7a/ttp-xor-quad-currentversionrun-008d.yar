rule TTP_XOR_QUAD_CurrentVersionRun_008d {
  strings:
    $key_008d = { 53 e2 [2] 77 ec [2] 5c c0 [2] 72 e2 [2] 66 f9 [2] 69 e3 [2] 77 fe [2] 75 ff [2] 6e f9 [2] 72 fe [2] 6e d1 }

  condition:
    any of them
}