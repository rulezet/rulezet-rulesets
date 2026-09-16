rule TTP_XOR_MULT_DOSStub_4cc2 {
  strings:
    $key_4cc2 = { 18 aa [2] 6c b2 [2] 2b b0 [2] 6c a1 [2] 22 ad [2] 2e a7 [2] 39 ac [2] 22 e2 [2] 1f }

  condition:
    any of them
}