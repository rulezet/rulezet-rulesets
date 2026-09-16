rule TTP_XOR_MULT_DOSStub_0dc2 {
  strings:
    $key_0dc2 = { 59 aa [2] 2d b2 [2] 6a b0 [2] 2d a1 [2] 63 ad [2] 6f a7 [2] 78 ac [2] 63 e2 [2] 5e }

  condition:
    any of them
}