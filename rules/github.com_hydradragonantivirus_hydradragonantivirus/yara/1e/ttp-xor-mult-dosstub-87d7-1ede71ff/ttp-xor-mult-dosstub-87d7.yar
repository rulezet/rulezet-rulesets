rule TTP_XOR_MULT_DOSStub_87d7 {
  strings:
    $key_87d7 = { d3 bf [2] a7 a7 [2] e0 a5 [2] a7 b4 [2] e9 b8 [2] e5 b2 [2] f2 b9 [2] e9 f7 [2] d4 }

  condition:
    any of them
}