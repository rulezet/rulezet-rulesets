rule TTP_XOR_MULT_DOSStub_14c3 {
  strings:
    $key_14c3 = { 40 ab [2] 34 b3 [2] 73 b1 [2] 34 a0 [2] 7a ac [2] 76 a6 [2] 61 ad [2] 7a e3 [2] 47 }

  condition:
    any of them
}