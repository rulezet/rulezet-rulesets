rule TTP_XOR_MULT_DOSStub_2a89 {
  strings:
    $key_2a89 = { 7e e1 [2] 0a f9 [2] 4d fb [2] 0a ea [2] 44 e6 [2] 48 ec [2] 5f e7 [2] 44 a9 [2] 79 }

  condition:
    any of them
}