rule TTP_XOR_MULT_DOSStub_0098 {
  strings:
    $key_0098 = { 54 f0 [2] 20 e8 [2] 67 ea [2] 20 fb [2] 6e f7 [2] 62 fd [2] 75 f6 [2] 6e b8 [2] 53 }

  condition:
    any of them
}