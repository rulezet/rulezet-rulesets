rule TTP_XOR_QUAD_CurrentVersionRun_418d {
  strings:
    $key_418d = { 12 e2 [2] 36 ec [2] 1d c0 [2] 33 e2 [2] 27 f9 [2] 28 e3 [2] 36 fe [2] 34 ff [2] 2f f9 [2] 33 fe [2] 2f d1 }

  condition:
    any of them
}