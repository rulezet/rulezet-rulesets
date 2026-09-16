rule TTP_XOR_MULT_DOSStub_08c3 {
  strings:
    $key_08c3 = { 5c ab [2] 28 b3 [2] 6f b1 [2] 28 a0 [2] 66 ac [2] 6a a6 [2] 7d ad [2] 66 e3 [2] 5b }

  condition:
    any of them
}