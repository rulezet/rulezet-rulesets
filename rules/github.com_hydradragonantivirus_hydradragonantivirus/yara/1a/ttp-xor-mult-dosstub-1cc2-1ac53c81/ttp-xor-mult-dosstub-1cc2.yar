rule TTP_XOR_MULT_DOSStub_1cc2 {
  strings:
    $key_1cc2 = { 48 aa [2] 3c b2 [2] 7b b0 [2] 3c a1 [2] 72 ad [2] 7e a7 [2] 69 ac [2] 72 e2 [2] 4f }

  condition:
    any of them
}