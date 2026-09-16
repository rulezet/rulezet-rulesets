rule TTP_XOR_MULT_DOSStub_7e84 {
  strings:
    $key_7e84 = { 2a ec [2] 5e f4 [2] 19 f6 [2] 5e e7 [2] 10 eb [2] 1c e1 [2] 0b ea [2] 10 a4 [2] 2d }

  condition:
    any of them
}