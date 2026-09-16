rule TTP_XOR_MULT_DOSStub_6cc2 {
  strings:
    $key_6cc2 = { 38 aa [2] 4c b2 [2] 0b b0 [2] 4c a1 [2] 02 ad [2] 0e a7 [2] 19 ac [2] 02 e2 [2] 3f }

  condition:
    any of them
}