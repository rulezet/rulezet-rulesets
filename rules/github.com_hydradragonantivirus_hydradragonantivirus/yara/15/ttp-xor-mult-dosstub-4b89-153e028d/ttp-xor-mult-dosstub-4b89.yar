rule TTP_XOR_MULT_DOSStub_4b89 {
  strings:
    $key_4b89 = { 1f e1 [2] 6b f9 [2] 2c fb [2] 6b ea [2] 25 e6 [2] 29 ec [2] 3e e7 [2] 25 a9 [2] 18 }

  condition:
    any of them
}