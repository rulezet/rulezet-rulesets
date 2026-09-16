rule TTP_XOR_MULT_DOSStub_4d89 {
  strings:
    $key_4d89 = { 19 e1 [2] 6d f9 [2] 2a fb [2] 6d ea [2] 23 e6 [2] 2f ec [2] 38 e7 [2] 23 a9 [2] 1e }

  condition:
    any of them
}