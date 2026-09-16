rule TTP_XOR_QUAD_CurrentVersionRun_418b {
  strings:
    $key_418b = { 12 e4 [2] 36 ea [2] 1d c6 [2] 33 e4 [2] 27 ff [2] 28 e5 [2] 36 f8 [2] 34 f9 [2] 2f ff [2] 33 f8 [2] 2f d7 }

  condition:
    any of them
}