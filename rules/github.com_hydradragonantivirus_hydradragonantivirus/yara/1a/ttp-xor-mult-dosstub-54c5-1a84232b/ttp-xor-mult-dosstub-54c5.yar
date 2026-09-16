rule TTP_XOR_MULT_DOSStub_54c5 {
  strings:
    $key_54c5 = { 00 ad [2] 74 b5 [2] 33 b7 [2] 74 a6 [2] 3a aa [2] 36 a0 [2] 21 ab [2] 3a e5 [2] 07 }

  condition:
    any of them
}