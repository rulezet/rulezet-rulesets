rule TTP_XOR_MULT_DOSStub_14c5 {
  strings:
    $key_14c5 = { 40 ad [2] 34 b5 [2] 73 b7 [2] 34 a6 [2] 7a aa [2] 76 a0 [2] 61 ab [2] 7a e5 [2] 47 }

  condition:
    any of them
}