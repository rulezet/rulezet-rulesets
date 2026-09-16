rule TTP_XOR_MULT_DOSStub_0b89 {
  strings:
    $key_0b89 = { 5f e1 [2] 2b f9 [2] 6c fb [2] 2b ea [2] 65 e6 [2] 69 ec [2] 7e e7 [2] 65 a9 [2] 58 }

  condition:
    any of them
}