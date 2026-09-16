rule TTP_XOR_MULT_DOSStub_3d89 {
  strings:
    $key_3d89 = { 69 e1 [2] 1d f9 [2] 5a fb [2] 1d ea [2] 53 e6 [2] 5f ec [2] 48 e7 [2] 53 a9 [2] 6e }

  condition:
    any of them
}