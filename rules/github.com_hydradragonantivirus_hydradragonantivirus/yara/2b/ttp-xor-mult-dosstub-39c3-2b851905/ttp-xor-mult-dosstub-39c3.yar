rule TTP_XOR_MULT_DOSStub_39c3 {
  strings:
    $key_39c3 = { 6d ab [2] 19 b3 [2] 5e b1 [2] 19 a0 [2] 57 ac [2] 5b a6 [2] 4c ad [2] 57 e3 [2] 6a }

  condition:
    any of them
}