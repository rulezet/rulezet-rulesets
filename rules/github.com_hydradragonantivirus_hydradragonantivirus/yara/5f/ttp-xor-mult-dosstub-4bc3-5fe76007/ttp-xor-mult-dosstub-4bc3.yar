rule TTP_XOR_MULT_DOSStub_4bc3 {
  strings:
    $key_4bc3 = { 1f ab [2] 6b b3 [2] 2c b1 [2] 6b a0 [2] 25 ac [2] 29 a6 [2] 3e ad [2] 25 e3 [2] 18 }

  condition:
    any of them
}