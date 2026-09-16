rule TTP_XOR_MULT_DOSStub_4686 {
  strings:
    $key_4686 = { 12 ee [2] 66 f6 [2] 21 f4 [2] 66 e5 [2] 28 e9 [2] 24 e3 [2] 33 e8 [2] 28 a6 [2] 15 }

  condition:
    any of them
}