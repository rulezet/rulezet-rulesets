rule TTP_XOR_MULT_DOSStub_7980 {
  strings:
    $key_7980 = { 2d e8 [2] 59 f0 [2] 1e f2 [2] 59 e3 [2] 17 ef [2] 1b e5 [2] 0c ee [2] 17 a0 [2] 2a }

  condition:
    any of them
}