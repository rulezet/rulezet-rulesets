rule TTP_XOR_QUAD_CurrentVersionRun_428d {
  strings:
    $key_428d = { 11 e2 [2] 35 ec [2] 1e c0 [2] 30 e2 [2] 24 f9 [2] 2b e3 [2] 35 fe [2] 37 ff [2] 2c f9 [2] 30 fe [2] 2c d1 }

  condition:
    any of them
}