rule TTP_XOR_MULT_DOSStub_86d7 {
  strings:
    $key_86d7 = { d2 bf [2] a6 a7 [2] e1 a5 [2] a6 b4 [2] e8 b8 [2] e4 b2 [2] f3 b9 [2] e8 f7 [2] d5 }

  condition:
    any of them
}