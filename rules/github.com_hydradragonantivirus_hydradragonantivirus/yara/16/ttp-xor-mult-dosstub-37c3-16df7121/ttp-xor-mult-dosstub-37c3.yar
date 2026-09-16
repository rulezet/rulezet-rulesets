rule TTP_XOR_MULT_DOSStub_37c3 {
  strings:
    $key_37c3 = { 63 ab [2] 17 b3 [2] 50 b1 [2] 17 a0 [2] 59 ac [2] 55 a6 [2] 42 ad [2] 59 e3 [2] 64 }

  condition:
    any of them
}