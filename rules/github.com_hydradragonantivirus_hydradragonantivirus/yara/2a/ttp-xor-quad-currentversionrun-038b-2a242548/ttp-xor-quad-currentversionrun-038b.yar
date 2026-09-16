rule TTP_XOR_QUAD_CurrentVersionRun_038b {
  strings:
    $key_038b = { 50 e4 [2] 74 ea [2] 5f c6 [2] 71 e4 [2] 65 ff [2] 6a e5 [2] 74 f8 [2] 76 f9 [2] 6d ff [2] 71 f8 [2] 6d d7 }

  condition:
    any of them
}