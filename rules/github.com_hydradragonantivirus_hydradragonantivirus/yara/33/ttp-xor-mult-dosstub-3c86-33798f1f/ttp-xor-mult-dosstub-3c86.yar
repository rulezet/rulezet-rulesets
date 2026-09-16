rule TTP_XOR_MULT_DOSStub_3c86 {
  strings:
    $key_3c86 = { 68 ee [2] 1c f6 [2] 5b f4 [2] 1c e5 [2] 52 e9 [2] 5e e3 [2] 49 e8 [2] 52 a6 [2] 6f }

  condition:
    any of them
}