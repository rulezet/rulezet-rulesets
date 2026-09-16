rule TTP_XOR_MULT_DOSStub_6cc3 {
  strings:
    $key_6cc3 = { 38 ab [2] 4c b3 [2] 0b b1 [2] 4c a0 [2] 02 ac [2] 0e a6 [2] 19 ad [2] 02 e3 [2] 3f }

  condition:
    any of them
}