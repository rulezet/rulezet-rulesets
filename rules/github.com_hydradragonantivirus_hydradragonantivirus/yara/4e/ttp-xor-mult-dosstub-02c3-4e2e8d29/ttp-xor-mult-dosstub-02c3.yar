rule TTP_XOR_MULT_DOSStub_02c3 {
  strings:
    $key_02c3 = { 56 ab [2] 22 b3 [2] 65 b1 [2] 22 a0 [2] 6c ac [2] 60 a6 [2] 77 ad [2] 6c e3 [2] 51 }

  condition:
    any of them
}