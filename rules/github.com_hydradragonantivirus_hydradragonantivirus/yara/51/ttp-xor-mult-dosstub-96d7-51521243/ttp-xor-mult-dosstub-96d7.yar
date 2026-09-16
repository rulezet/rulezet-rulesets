rule TTP_XOR_MULT_DOSStub_96d7 {
  strings:
    $key_96d7 = { c2 bf [2] b6 a7 [2] f1 a5 [2] b6 b4 [2] f8 b8 [2] f4 b2 [2] e3 b9 [2] f8 f7 [2] c5 }

  condition:
    any of them
}