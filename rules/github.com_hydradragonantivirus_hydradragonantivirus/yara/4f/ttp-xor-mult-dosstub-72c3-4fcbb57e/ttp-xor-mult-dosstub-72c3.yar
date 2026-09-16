rule TTP_XOR_MULT_DOSStub_72c3 {
  strings:
    $key_72c3 = { 26 ab [2] 52 b3 [2] 15 b1 [2] 52 a0 [2] 1c ac [2] 10 a6 [2] 07 ad [2] 1c e3 [2] 21 }

  condition:
    any of them
}