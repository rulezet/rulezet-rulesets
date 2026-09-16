rule TTP_XOR_MULT_DOSStub_3b89 {
  strings:
    $key_3b89 = { 6f e1 [2] 1b f9 [2] 5c fb [2] 1b ea [2] 55 e6 [2] 59 ec [2] 4e e7 [2] 55 a9 [2] 68 }

  condition:
    any of them
}