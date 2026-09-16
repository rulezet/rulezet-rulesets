rule TTP_XOR_MULT_DOSStub_5c86 {
  strings:
    $key_5c86 = { 08 ee [2] 7c f6 [2] 3b f4 [2] 7c e5 [2] 32 e9 [2] 3e e3 [2] 29 e8 [2] 32 a6 [2] 0f }

  condition:
    any of them
}