rule TTP_XOR_QUAD_CurrentVersionRun_6d8b {
  strings:
    $key_6d8b = { 3e e4 [2] 1a ea [2] 31 c6 [2] 1f e4 [2] 0b ff [2] 04 e5 [2] 1a f8 [2] 18 f9 [2] 03 ff [2] 1f f8 [2] 03 d7 }

  condition:
    any of them
}