rule TTP_XOR_QUAD_CurrentVersionRun_718b {
  strings:
    $key_718b = { 22 e4 [2] 06 ea [2] 2d c6 [2] 03 e4 [2] 17 ff [2] 18 e5 [2] 06 f8 [2] 04 f9 [2] 1f ff [2] 03 f8 [2] 1f d7 }

  condition:
    any of them
}