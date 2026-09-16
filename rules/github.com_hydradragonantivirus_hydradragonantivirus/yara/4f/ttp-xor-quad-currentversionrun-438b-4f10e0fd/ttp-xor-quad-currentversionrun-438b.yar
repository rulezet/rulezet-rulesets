rule TTP_XOR_QUAD_CurrentVersionRun_438b {
  strings:
    $key_438b = { 10 e4 [2] 34 ea [2] 1f c6 [2] 31 e4 [2] 25 ff [2] 2a e5 [2] 34 f8 [2] 36 f9 [2] 2d ff [2] 31 f8 [2] 2d d7 }

  condition:
    any of them
}