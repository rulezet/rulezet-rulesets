rule TTP_XOR_MULT_DOSStub_81d6 {
  strings:
    $key_81d6 = { d5 be [2] a1 a6 [2] e6 a4 [2] a1 b5 [2] ef b9 [2] e3 b3 [2] f4 b8 [2] ef f6 [2] d2 }

  condition:
    any of them
}