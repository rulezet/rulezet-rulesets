rule TTP_XOR_MULT_DOSStub_6d89 {
  strings:
    $key_6d89 = { 39 e1 [2] 4d f9 [2] 0a fb [2] 4d ea [2] 03 e6 [2] 0f ec [2] 18 e7 [2] 03 a9 [2] 3e }

  condition:
    any of them
}