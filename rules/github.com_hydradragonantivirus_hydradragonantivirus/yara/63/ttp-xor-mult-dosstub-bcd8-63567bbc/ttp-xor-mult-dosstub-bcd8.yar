rule TTP_XOR_MULT_DOSStub_bcd8 {
  strings:
    $key_bcd8 = { e8 b0 [2] 9c a8 [2] db aa [2] 9c bb [2] d2 b7 [2] de bd [2] c9 b6 [2] d2 f8 [2] ef }

  condition:
    any of them
}