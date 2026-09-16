rule TTP_XOR_MULT_DOSStub_7cc0 {
  strings:
    $key_7cc0 = { 28 a8 [2] 5c b0 [2] 1b b2 [2] 5c a3 [2] 12 af [2] 1e a5 [2] 09 ae [2] 12 e0 [2] 2f }

  condition:
    any of them
}