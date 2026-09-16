rule TTP_XOR_MULT_DOSStub_1d89 {
  strings:
    $key_1d89 = { 49 e1 [2] 3d f9 [2] 7a fb [2] 3d ea [2] 73 e6 [2] 7f ec [2] 68 e7 [2] 73 a9 [2] 4e }

  condition:
    any of them
}