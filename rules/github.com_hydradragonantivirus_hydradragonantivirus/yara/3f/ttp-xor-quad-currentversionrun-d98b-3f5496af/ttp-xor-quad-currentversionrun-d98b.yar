rule TTP_XOR_QUAD_CurrentVersionRun_d98b {
  strings:
    $key_d98b = { 8a e4 [2] ae ea [2] 85 c6 [2] ab e4 [2] bf ff [2] b0 e5 [2] ae f8 [2] ac f9 [2] b7 ff [2] ab f8 [2] b7 d7 }

  condition:
    any of them
}