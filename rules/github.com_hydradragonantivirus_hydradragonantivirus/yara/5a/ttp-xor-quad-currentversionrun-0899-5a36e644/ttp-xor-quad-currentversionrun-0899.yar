rule TTP_XOR_QUAD_CurrentVersionRun_0899 {
  strings:
    $key_0899 = { 5b f6 [2] 7f f8 [2] 54 d4 [2] 7a f6 [2] 6e ed [2] 61 f7 [2] 7f ea [2] 7d eb [2] 66 ed [2] 7a ea [2] 66 c5 }

  condition:
    any of them
}