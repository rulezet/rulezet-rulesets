rule TTP_XOR_MULT_DOSStub_7bc2 {
  strings:
    $key_7bc2 = { 2f aa [2] 5b b2 [2] 1c b0 [2] 5b a1 [2] 15 ad [2] 19 a7 [2] 0e ac [2] 15 e2 [2] 28 }

  condition:
    any of them
}