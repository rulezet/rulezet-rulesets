rule TTP_XOR_MULT_DOSStub_bcd6 {
  strings:
    $key_bcd6 = { e8 be [2] 9c a6 [2] db a4 [2] 9c b5 [2] d2 b9 [2] de b3 [2] c9 b8 [2] d2 f6 [2] ef }

  condition:
    any of them
}