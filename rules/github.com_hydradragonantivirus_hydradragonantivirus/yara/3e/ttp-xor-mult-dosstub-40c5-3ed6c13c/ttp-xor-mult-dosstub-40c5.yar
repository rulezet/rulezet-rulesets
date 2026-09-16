rule TTP_XOR_MULT_DOSStub_40c5 {
  strings:
    $key_40c5 = { 14 ad [2] 60 b5 [2] 27 b7 [2] 60 a6 [2] 2e aa [2] 22 a0 [2] 35 ab [2] 2e e5 [2] 13 }

  condition:
    any of them
}