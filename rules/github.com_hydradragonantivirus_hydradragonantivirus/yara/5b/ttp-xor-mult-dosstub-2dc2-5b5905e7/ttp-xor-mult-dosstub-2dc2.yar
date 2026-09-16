rule TTP_XOR_MULT_DOSStub_2dc2 {
  strings:
    $key_2dc2 = { 79 aa [2] 0d b2 [2] 4a b0 [2] 0d a1 [2] 43 ad [2] 4f a7 [2] 58 ac [2] 43 e2 [2] 7e }

  condition:
    any of them
}