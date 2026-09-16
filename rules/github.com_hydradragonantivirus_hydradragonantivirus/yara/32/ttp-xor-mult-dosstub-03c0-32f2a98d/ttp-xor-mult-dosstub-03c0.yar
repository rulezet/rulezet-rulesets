rule TTP_XOR_MULT_DOSStub_03c0 {
  strings:
    $key_03c0 = { 57 a8 [2] 23 b0 [2] 64 b2 [2] 23 a3 [2] 6d af [2] 61 a5 [2] 76 ae [2] 6d e0 [2] 50 }

  condition:
    any of them
}