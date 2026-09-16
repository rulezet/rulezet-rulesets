rule TTP_XOR_MULT_DOSStub_0096 {
  strings:
    $key_0096 = { 54 fe [2] 20 e6 [2] 67 e4 [2] 20 f5 [2] 6e f9 [2] 62 f3 [2] 75 f8 [2] 6e b6 [2] 53 }

  condition:
    any of them
}