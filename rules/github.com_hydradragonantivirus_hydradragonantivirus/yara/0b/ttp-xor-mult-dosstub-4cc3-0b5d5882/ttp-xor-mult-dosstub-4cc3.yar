rule TTP_XOR_MULT_DOSStub_4cc3 {
  strings:
    $key_4cc3 = { 18 ab [2] 6c b3 [2] 2b b1 [2] 6c a0 [2] 22 ac [2] 2e a6 [2] 39 ad [2] 22 e3 [2] 1f }

  condition:
    any of them
}