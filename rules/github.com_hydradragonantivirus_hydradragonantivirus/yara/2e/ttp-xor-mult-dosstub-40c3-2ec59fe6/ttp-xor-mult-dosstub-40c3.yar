rule TTP_XOR_MULT_DOSStub_40c3 {
  strings:
    $key_40c3 = { 14 ab [2] 60 b3 [2] 27 b1 [2] 60 a0 [2] 2e ac [2] 22 a6 [2] 35 ad [2] 2e e3 [2] 13 }

  condition:
    any of them
}