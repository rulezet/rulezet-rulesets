rule TTP_XOR_QUAD_CurrentVersionRun_338b {
  strings:
    $key_338b = { 60 e4 [2] 44 ea [2] 6f c6 [2] 41 e4 [2] 55 ff [2] 5a e5 [2] 44 f8 [2] 46 f9 [2] 5d ff [2] 41 f8 [2] 5d d7 }

  condition:
    any of them
}