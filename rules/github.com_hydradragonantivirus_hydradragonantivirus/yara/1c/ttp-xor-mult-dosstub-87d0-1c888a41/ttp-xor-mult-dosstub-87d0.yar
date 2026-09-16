rule TTP_XOR_MULT_DOSStub_87d0 {
  strings:
    $key_87d0 = { d3 b8 [2] a7 a0 [2] e0 a2 [2] a7 b3 [2] e9 bf [2] e5 b5 [2] f2 be [2] e9 f0 [2] d4 }

  condition:
    any of them
}