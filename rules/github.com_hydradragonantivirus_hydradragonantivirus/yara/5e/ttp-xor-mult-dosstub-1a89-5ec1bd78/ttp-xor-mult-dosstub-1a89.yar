rule TTP_XOR_MULT_DOSStub_1a89 {
  strings:
    $key_1a89 = { 4e e1 [2] 3a f9 [2] 7d fb [2] 3a ea [2] 74 e6 [2] 78 ec [2] 6f e7 [2] 74 a9 [2] 49 }

  condition:
    any of them
}