rule TTP_XOR_MULT_DOSStub_bcd1 {
  strings:
    $key_bcd1 = { e8 b9 [2] 9c a1 [2] db a3 [2] 9c b2 [2] d2 be [2] de b4 [2] c9 bf [2] d2 f1 [2] ef }

  condition:
    any of them
}