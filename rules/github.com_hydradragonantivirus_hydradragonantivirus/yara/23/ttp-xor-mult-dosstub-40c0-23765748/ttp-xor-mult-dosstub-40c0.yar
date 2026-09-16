rule TTP_XOR_MULT_DOSStub_40c0 {
  strings:
    $key_40c0 = { 14 a8 [2] 60 b0 [2] 27 b2 [2] 60 a3 [2] 2e af [2] 22 a5 [2] 35 ae [2] 2e e0 [2] 13 }

  condition:
    any of them
}