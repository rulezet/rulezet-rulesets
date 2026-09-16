rule TTP_XOR_MULT_DOSStub_1485 {
  strings:
    $key_1485 = { 40 ed [2] 34 f5 [2] 73 f7 [2] 34 e6 [2] 7a ea [2] 76 e0 [2] 61 eb [2] 7a a5 [2] 47 }

  condition:
    any of them
}