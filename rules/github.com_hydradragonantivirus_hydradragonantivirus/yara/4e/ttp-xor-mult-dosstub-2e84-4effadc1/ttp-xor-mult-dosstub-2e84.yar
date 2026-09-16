rule TTP_XOR_MULT_DOSStub_2e84 {
  strings:
    $key_2e84 = { 7a ec [2] 0e f4 [2] 49 f6 [2] 0e e7 [2] 40 eb [2] 4c e1 [2] 5b ea [2] 40 a4 [2] 7d }

  condition:
    any of them
}