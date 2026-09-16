rule TTP_XOR_MULT_DOSStub_35c3 {
  strings:
    $key_35c3 = { 61 ab [2] 15 b3 [2] 52 b1 [2] 15 a0 [2] 5b ac [2] 57 a6 [2] 40 ad [2] 5b e3 [2] 66 }

  condition:
    any of them
}