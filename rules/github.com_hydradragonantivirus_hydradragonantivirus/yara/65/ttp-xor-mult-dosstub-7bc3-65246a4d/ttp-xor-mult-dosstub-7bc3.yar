rule TTP_XOR_MULT_DOSStub_7bc3 {
  strings:
    $key_7bc3 = { 2f ab [2] 5b b3 [2] 1c b1 [2] 5b a0 [2] 15 ac [2] 19 a6 [2] 0e ad [2] 15 e3 [2] 28 }

  condition:
    any of them
}