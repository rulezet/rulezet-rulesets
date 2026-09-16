rule TTP_XOR_MULT_DOSStub_4dc2 {
  strings:
    $key_4dc2 = { 19 aa [2] 6d b2 [2] 2a b0 [2] 6d a1 [2] 23 ad [2] 2f a7 [2] 38 ac [2] 23 e2 [2] 1e }

  condition:
    any of them
}