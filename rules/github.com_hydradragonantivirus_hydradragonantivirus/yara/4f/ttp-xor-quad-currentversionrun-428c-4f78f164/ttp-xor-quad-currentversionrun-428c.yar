rule TTP_XOR_QUAD_CurrentVersionRun_428c {
  strings:
    $key_428c = { 11 e3 [2] 35 ed [2] 1e c1 [2] 30 e3 [2] 24 f8 [2] 2b e2 [2] 35 ff [2] 37 fe [2] 2c f8 [2] 30 ff [2] 2c d0 }

  condition:
    any of them
}