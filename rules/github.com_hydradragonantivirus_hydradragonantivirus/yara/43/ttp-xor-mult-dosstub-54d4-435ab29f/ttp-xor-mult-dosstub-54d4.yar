rule TTP_XOR_MULT_DOSStub_54d4 {
  strings:
    $key_54d4 = { 00 bc [2] 74 a4 [2] 33 a6 [2] 74 b7 [2] 3a bb [2] 36 b1 [2] 21 ba [2] 3a f4 [2] 07 }

  condition:
    any of them
}