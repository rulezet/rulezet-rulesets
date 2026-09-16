rule TTP_XOR_QUAD_CurrentVersionRun_f899 {
  strings:
    $key_f899 = { ab f6 [2] 8f f8 [2] a4 d4 [2] 8a f6 [2] 9e ed [2] 91 f7 [2] 8f ea [2] 8d eb [2] 96 ed [2] 8a ea [2] 96 c5 }

  condition:
    any of them
}