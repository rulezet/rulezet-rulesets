rule TTP_XOR_MULT_DOSStub_5b89 {
  strings:
    $key_5b89 = { 0f e1 [2] 7b f9 [2] 3c fb [2] 7b ea [2] 35 e6 [2] 39 ec [2] 2e e7 [2] 35 a9 [2] 08 }

  condition:
    any of them
}