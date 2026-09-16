rule TTP_XOR_MULT_DOSStub_bcd4 {
  strings:
    $key_bcd4 = { e8 bc [2] 9c a4 [2] db a6 [2] 9c b7 [2] d2 bb [2] de b1 [2] c9 ba [2] d2 f4 [2] ef }

  condition:
    any of them
}