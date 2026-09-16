rule TTP_XOR_MULT_DOSStub_1c86 {
  strings:
    $key_1c86 = { 48 ee [2] 3c f6 [2] 7b f4 [2] 3c e5 [2] 72 e9 [2] 7e e3 [2] 69 e8 [2] 72 a6 [2] 4f }

  condition:
    any of them
}