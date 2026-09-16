rule TTP_XOR_MULT_DOSStub_03c5 {
  strings:
    $key_03c5 = { 57 ad [2] 23 b5 [2] 64 b7 [2] 23 a6 [2] 6d aa [2] 61 a0 [2] 76 ab [2] 6d e5 [2] 50 }

  condition:
    any of them
}