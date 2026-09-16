rule TTP_XOR_MULT_DOSStub_4086 {
  strings:
    $key_4086 = { 14 ee [2] 60 f6 [2] 27 f4 [2] 60 e5 [2] 2e e9 [2] 22 e3 [2] 35 e8 [2] 2e a6 [2] 13 }

  condition:
    any of them
}