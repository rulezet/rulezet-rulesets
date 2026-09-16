rule TTP_XOR_MULT_DOSStub_4a89 {
  strings:
    $key_4a89 = { 1e e1 [2] 6a f9 [2] 2d fb [2] 6a ea [2] 24 e6 [2] 28 ec [2] 3f e7 [2] 24 a9 [2] 19 }

  condition:
    any of them
}