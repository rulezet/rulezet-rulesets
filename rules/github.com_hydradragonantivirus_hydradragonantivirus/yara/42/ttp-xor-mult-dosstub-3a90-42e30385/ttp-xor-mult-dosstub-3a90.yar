rule TTP_XOR_MULT_DOSStub_3a90 {
  strings:
    $key_3a90 = { 6e f8 [2] 1a e0 [2] 5d e2 [2] 1a f3 [2] 54 ff [2] 58 f5 [2] 4f fe [2] 54 b0 [2] 69 }

  condition:
    any of them
}