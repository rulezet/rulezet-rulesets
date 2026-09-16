rule TTP_XOR_MULT_DOSStub_54d9 {
  strings:
    $key_54d9 = { 00 b1 [2] 74 a9 [2] 33 ab [2] 74 ba [2] 3a b6 [2] 36 bc [2] 21 b7 [2] 3a f9 [2] 07 }

  condition:
    any of them
}