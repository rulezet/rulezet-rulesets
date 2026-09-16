rule TTP_XOR_QUAD_CurrentVersionRun_3f8b {
  strings:
    $key_3f8b = { 6c e4 [2] 48 ea [2] 63 c6 [2] 4d e4 [2] 59 ff [2] 56 e5 [2] 48 f8 [2] 4a f9 [2] 51 ff [2] 4d f8 [2] 51 d7 }

  condition:
    any of them
}