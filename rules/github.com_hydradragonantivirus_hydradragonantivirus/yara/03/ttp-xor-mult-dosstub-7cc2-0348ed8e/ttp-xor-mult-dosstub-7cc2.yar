rule TTP_XOR_MULT_DOSStub_7cc2 {
  strings:
    $key_7cc2 = { 28 aa [2] 5c b2 [2] 1b b0 [2] 5c a1 [2] 12 ad [2] 1e a7 [2] 09 ac [2] 12 e2 [2] 2f }

  condition:
    any of them
}