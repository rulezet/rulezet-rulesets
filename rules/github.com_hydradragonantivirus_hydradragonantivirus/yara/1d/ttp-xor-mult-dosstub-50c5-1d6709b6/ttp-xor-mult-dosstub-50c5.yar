rule TTP_XOR_MULT_DOSStub_50c5 {
  strings:
    $key_50c5 = { 04 ad [2] 70 b5 [2] 37 b7 [2] 70 a6 [2] 3e aa [2] 32 a0 [2] 25 ab [2] 3e e5 [2] 03 }

  condition:
    any of them
}