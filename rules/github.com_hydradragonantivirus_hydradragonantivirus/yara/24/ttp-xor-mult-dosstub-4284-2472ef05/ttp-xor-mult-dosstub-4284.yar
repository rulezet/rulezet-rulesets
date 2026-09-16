rule TTP_XOR_MULT_DOSStub_4284 {
  strings:
    $key_4284 = { 16 ec [2] 62 f4 [2] 25 f6 [2] 62 e7 [2] 2c eb [2] 20 e1 [2] 37 ea [2] 2c a4 [2] 11 }

  condition:
    any of them
}