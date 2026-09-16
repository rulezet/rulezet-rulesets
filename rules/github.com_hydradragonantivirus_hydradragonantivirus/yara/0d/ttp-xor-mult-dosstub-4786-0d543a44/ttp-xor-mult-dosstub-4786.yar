rule TTP_XOR_MULT_DOSStub_4786 {
  strings:
    $key_4786 = { 13 ee [2] 67 f6 [2] 20 f4 [2] 67 e5 [2] 29 e9 [2] 25 e3 [2] 32 e8 [2] 29 a6 [2] 14 }

  condition:
    any of them
}