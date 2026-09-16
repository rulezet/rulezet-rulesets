rule TTP_XOR_QUAD_CurrentVersionRun_138b {
  strings:
    $key_138b = { 40 e4 [2] 64 ea [2] 4f c6 [2] 61 e4 [2] 75 ff [2] 7a e5 [2] 64 f8 [2] 66 f9 [2] 7d ff [2] 61 f8 [2] 7d d7 }

  condition:
    any of them
}