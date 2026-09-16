rule TTP_XOR_MULT_DOSStub_2dc3 {
  strings:
    $key_2dc3 = { 79 ab [2] 0d b3 [2] 4a b1 [2] 0d a0 [2] 43 ac [2] 4f a6 [2] 58 ad [2] 43 e3 [2] 7e }

  condition:
    any of them
}