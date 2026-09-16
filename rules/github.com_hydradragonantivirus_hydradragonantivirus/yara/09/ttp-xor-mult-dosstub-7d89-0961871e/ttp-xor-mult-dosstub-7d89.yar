rule TTP_XOR_MULT_DOSStub_7d89 {
  strings:
    $key_7d89 = { 29 e1 [2] 5d f9 [2] 1a fb [2] 5d ea [2] 13 e6 [2] 1f ec [2] 08 e7 [2] 13 a9 [2] 2e }

  condition:
    any of them
}