rule TTP_XOR_MULT_DOSStub_32c5 {
  strings:
    $key_32c5 = { 66 ad [2] 12 b5 [2] 55 b7 [2] 12 a6 [2] 5c aa [2] 50 a0 [2] 47 ab [2] 5c e5 [2] 61 }

  condition:
    any of them
}