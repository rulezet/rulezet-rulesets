rule TTP_XOR_MULT_DOSStub_2cc3 {
  strings:
    $key_2cc3 = { 78 ab [2] 0c b3 [2] 4b b1 [2] 0c a0 [2] 42 ac [2] 4e a6 [2] 59 ad [2] 42 e3 [2] 7f }

  condition:
    any of them
}