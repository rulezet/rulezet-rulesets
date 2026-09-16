rule TTP_XOR_MULT_DOSStub_68c3 {
  strings:
    $key_68c3 = { 3c ab [2] 48 b3 [2] 0f b1 [2] 48 a0 [2] 06 ac [2] 0a a6 [2] 1d ad [2] 06 e3 [2] 3b }

  condition:
    any of them
}