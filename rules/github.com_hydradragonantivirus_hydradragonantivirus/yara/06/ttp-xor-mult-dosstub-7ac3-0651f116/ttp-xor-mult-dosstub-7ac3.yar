rule TTP_XOR_MULT_DOSStub_7ac3 {
  strings:
    $key_7ac3 = { 2e ab [2] 5a b3 [2] 1d b1 [2] 5a a0 [2] 14 ac [2] 18 a6 [2] 0f ad [2] 14 e3 [2] 29 }

  condition:
    any of them
}