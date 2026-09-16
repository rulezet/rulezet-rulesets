rule TTP_XOR_MULT_DOSStub_95d7 {
  strings:
    $key_95d7 = { c1 bf [2] b5 a7 [2] f2 a5 [2] b5 b4 [2] fb b8 [2] f7 b2 [2] e0 b9 [2] fb f7 [2] c6 }

  condition:
    any of them
}