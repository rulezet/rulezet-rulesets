rule TTP_XOR_MULT_DOSStub_4990 {
  strings:
    $key_4990 = { 1d f8 [2] 69 e0 [2] 2e e2 [2] 69 f3 [2] 27 ff [2] 2b f5 [2] 3c fe [2] 27 b0 [2] 1a }

  condition:
    any of them
}