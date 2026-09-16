rule TTP_XOR_QUAD_CurrentVersionRun_458b {
  strings:
    $key_458b = { 16 e4 [2] 32 ea [2] 19 c6 [2] 37 e4 [2] 23 ff [2] 2c e5 [2] 32 f8 [2] 30 f9 [2] 2b ff [2] 37 f8 [2] 2b d7 }

  condition:
    any of them
}