rule TTP_XOR_MULT_DOSStub_0e84 {
  strings:
    $key_0e84 = { 5a ec [2] 2e f4 [2] 69 f6 [2] 2e e7 [2] 60 eb [2] 6c e1 [2] 7b ea [2] 60 a4 [2] 5d }

  condition:
    any of them
}