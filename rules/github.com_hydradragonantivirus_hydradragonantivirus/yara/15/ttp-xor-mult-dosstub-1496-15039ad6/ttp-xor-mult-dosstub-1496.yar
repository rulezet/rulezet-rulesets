rule TTP_XOR_MULT_DOSStub_1496 {
  strings:
    $key_1496 = { 40 fe [2] 34 e6 [2] 73 e4 [2] 34 f5 [2] 7a f9 [2] 76 f3 [2] 61 f8 [2] 7a b6 [2] 47 }

  condition:
    any of them
}