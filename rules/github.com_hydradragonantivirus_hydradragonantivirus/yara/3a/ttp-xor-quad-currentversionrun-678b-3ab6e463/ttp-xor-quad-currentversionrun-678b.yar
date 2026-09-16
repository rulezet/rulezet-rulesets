rule TTP_XOR_QUAD_CurrentVersionRun_678b {
  strings:
    $key_678b = { 34 e4 [2] 10 ea [2] 3b c6 [2] 15 e4 [2] 01 ff [2] 0e e5 [2] 10 f8 [2] 12 f9 [2] 09 ff [2] 15 f8 [2] 09 d7 }

  condition:
    any of them
}