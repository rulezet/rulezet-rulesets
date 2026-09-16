rule TTP_XOR_QUAD_CurrentVersionRun_658b {
  strings:
    $key_658b = { 36 e4 [2] 12 ea [2] 39 c6 [2] 17 e4 [2] 03 ff [2] 0c e5 [2] 12 f8 [2] 10 f9 [2] 0b ff [2] 17 f8 [2] 0b d7 }

  condition:
    any of them
}