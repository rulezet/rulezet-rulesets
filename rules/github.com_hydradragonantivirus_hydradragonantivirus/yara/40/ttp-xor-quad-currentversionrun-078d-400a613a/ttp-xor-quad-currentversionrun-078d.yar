rule TTP_XOR_QUAD_CurrentVersionRun_078d {
  strings:
    $key_078d = { 54 e2 [2] 70 ec [2] 5b c0 [2] 75 e2 [2] 61 f9 [2] 6e e3 [2] 70 fe [2] 72 ff [2] 69 f9 [2] 75 fe [2] 69 d1 }

  condition:
    any of them
}