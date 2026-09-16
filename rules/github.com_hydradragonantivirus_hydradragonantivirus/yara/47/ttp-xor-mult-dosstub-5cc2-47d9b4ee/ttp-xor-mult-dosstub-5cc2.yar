rule TTP_XOR_MULT_DOSStub_5cc2 {
  strings:
    $key_5cc2 = { 08 aa [2] 7c b2 [2] 3b b0 [2] 7c a1 [2] 32 ad [2] 3e a7 [2] 29 ac [2] 32 e2 [2] 0f }

  condition:
    any of them
}