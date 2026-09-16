rule TTP_XOR_MULT_DOSStub_81d1 {
  strings:
    $key_81d1 = { d5 b9 [2] a1 a1 [2] e6 a3 [2] a1 b2 [2] ef be [2] e3 b4 [2] f4 bf [2] ef f1 [2] d2 }

  condition:
    any of them
}