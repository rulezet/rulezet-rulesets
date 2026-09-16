rule TTP_XOR_MULT_DOSStub_bcd0 {
  strings:
    $key_bcd0 = { e8 b8 [2] 9c a0 [2] db a2 [2] 9c b3 [2] d2 bf [2] de b5 [2] c9 be [2] d2 f0 [2] ef }

  condition:
    any of them
}