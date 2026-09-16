rule TTP_XOR_MULT_DOSStub_1497 {
  strings:
    $key_1497 = { 40 ff [2] 34 e7 [2] 73 e5 [2] 34 f4 [2] 7a f8 [2] 76 f2 [2] 61 f9 [2] 7a b7 [2] 47 }

  condition:
    any of them
}