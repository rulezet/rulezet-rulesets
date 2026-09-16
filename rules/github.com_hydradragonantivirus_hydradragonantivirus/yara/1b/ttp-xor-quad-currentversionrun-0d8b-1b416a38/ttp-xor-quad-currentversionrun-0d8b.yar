rule TTP_XOR_QUAD_CurrentVersionRun_0d8b {
  strings:
    $key_0d8b = { 5e e4 [2] 7a ea [2] 51 c6 [2] 7f e4 [2] 6b ff [2] 64 e5 [2] 7a f8 [2] 78 f9 [2] 63 ff [2] 7f f8 [2] 63 d7 }

  condition:
    any of them
}