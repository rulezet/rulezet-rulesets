rule TTP_XOR_MULT_DOSStub_7cc3 {
  strings:
    $key_7cc3 = { 28 ab [2] 5c b3 [2] 1b b1 [2] 5c a0 [2] 12 ac [2] 1e a6 [2] 09 ad [2] 12 e3 [2] 2f }

  condition:
    any of them
}