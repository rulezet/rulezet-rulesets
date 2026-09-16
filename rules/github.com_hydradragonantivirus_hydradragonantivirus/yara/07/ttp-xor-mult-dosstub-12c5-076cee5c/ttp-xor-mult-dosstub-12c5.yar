rule TTP_XOR_MULT_DOSStub_12c5 {
  strings:
    $key_12c5 = { 46 ad [2] 32 b5 [2] 75 b7 [2] 32 a6 [2] 7c aa [2] 70 a0 [2] 67 ab [2] 7c e5 [2] 41 }

  condition:
    any of them
}