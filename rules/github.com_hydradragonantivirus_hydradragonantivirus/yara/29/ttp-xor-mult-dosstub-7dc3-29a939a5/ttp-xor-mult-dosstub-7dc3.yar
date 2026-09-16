rule TTP_XOR_MULT_DOSStub_7dc3 {
  strings:
    $key_7dc3 = { 29 ab [2] 5d b3 [2] 1a b1 [2] 5d a0 [2] 13 ac [2] 1f a6 [2] 08 ad [2] 13 e3 [2] 2e }

  condition:
    any of them
}