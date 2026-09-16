rule TTP_XOR_MULT_DOSStub_5497 {
  strings:
    $key_5497 = { 00 ff [2] 74 e7 [2] 33 e5 [2] 74 f4 [2] 3a f8 [2] 36 f2 [2] 21 f9 [2] 3a b7 [2] 07 }

  condition:
    any of them
}