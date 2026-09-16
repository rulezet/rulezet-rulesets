rule TTP_XOR_QUAD_CurrentVersionRun_6899 {
  strings:
    $key_6899 = { 3b f6 [2] 1f f8 [2] 34 d4 [2] 1a f6 [2] 0e ed [2] 01 f7 [2] 1f ea [2] 1d eb [2] 06 ed [2] 1a ea [2] 06 c5 }

  condition:
    any of them
}