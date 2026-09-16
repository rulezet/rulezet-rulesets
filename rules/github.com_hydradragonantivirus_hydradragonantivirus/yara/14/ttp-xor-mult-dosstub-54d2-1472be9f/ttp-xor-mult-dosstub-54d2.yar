rule TTP_XOR_MULT_DOSStub_54d2 {
  strings:
    $key_54d2 = { 00 ba [2] 74 a2 [2] 33 a0 [2] 74 b1 [2] 3a bd [2] 36 b7 [2] 21 bc [2] 3a f2 [2] 07 }

  condition:
    any of them
}