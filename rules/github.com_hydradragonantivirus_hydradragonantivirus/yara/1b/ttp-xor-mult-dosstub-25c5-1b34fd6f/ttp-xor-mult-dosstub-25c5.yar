rule TTP_XOR_MULT_DOSStub_25c5 {
  strings:
    $key_25c5 = { 71 ad [2] 05 b5 [2] 42 b7 [2] 05 a6 [2] 4b aa [2] 47 a0 [2] 50 ab [2] 4b e5 [2] 76 }

  condition:
    any of them
}