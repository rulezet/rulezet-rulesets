rule TTP_XOR_MULT_DOSStub_0bc2 {
  strings:
    $key_0bc2 = { 5f aa [2] 2b b2 [2] 6c b0 [2] 2b a1 [2] 65 ad [2] 69 a7 [2] 7e ac [2] 65 e2 [2] 58 }

  condition:
    any of them
}