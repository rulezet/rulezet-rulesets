rule TTP_XOR_MULT_DOSStub_04c0 {
  strings:
    $key_04c0 = { 50 a8 [2] 24 b0 [2] 63 b2 [2] 24 a3 [2] 6a af [2] 66 a5 [2] 71 ae [2] 6a e0 [2] 57 }

  condition:
    any of them
}