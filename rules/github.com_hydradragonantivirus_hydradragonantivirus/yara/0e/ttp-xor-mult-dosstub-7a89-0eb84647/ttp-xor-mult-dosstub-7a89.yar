rule TTP_XOR_MULT_DOSStub_7a89 {
  strings:
    $key_7a89 = { 2e e1 [2] 5a f9 [2] 1d fb [2] 5a ea [2] 14 e6 [2] 18 ec [2] 0f e7 [2] 14 a9 [2] 29 }

  condition:
    any of them
}