rule TTP_XOR_MULT_DOSStub_1486 {
  strings:
    $key_1486 = { 40 ee [2] 34 f6 [2] 73 f4 [2] 34 e5 [2] 7a e9 [2] 76 e3 [2] 61 e8 [2] 7a a6 [2] 47 }

  condition:
    any of them
}