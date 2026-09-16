rule TTP_XOR_MULT_DOSStub_64c5 {
  strings:
    $key_64c5 = { 30 ad [2] 44 b5 [2] 03 b7 [2] 44 a6 [2] 0a aa [2] 06 a0 [2] 11 ab [2] 0a e5 [2] 37 }

  condition:
    any of them
}