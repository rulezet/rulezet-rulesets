rule TTP_XOR_MULT_DOSStub_bcd5 {
  strings:
    $key_bcd5 = { e8 bd [2] 9c a5 [2] db a7 [2] 9c b6 [2] d2 ba [2] de b0 [2] c9 bb [2] d2 f5 [2] ef }

  condition:
    any of them
}