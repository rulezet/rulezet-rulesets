rule TTP_XOR_MULT_DOSStub_49c3 {
  strings:
    $key_49c3 = { 1d ab [2] 69 b3 [2] 2e b1 [2] 69 a0 [2] 27 ac [2] 2b a6 [2] 3c ad [2] 27 e3 [2] 1a }

  condition:
    any of them
}