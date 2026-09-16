rule TTP_XOR_MULT_DOSStub_7dc2 {
  strings:
    $key_7dc2 = { 29 aa [2] 5d b2 [2] 1a b0 [2] 5d a1 [2] 13 ad [2] 1f a7 [2] 08 ac [2] 13 e2 [2] 2e }

  condition:
    any of them
}