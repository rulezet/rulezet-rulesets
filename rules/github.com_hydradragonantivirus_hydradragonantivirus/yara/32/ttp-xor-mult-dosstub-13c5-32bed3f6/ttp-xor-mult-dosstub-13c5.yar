rule TTP_XOR_MULT_DOSStub_13c5 {
  strings:
    $key_13c5 = { 47 ad [2] 33 b5 [2] 74 b7 [2] 33 a6 [2] 7d aa [2] 71 a0 [2] 66 ab [2] 7d e5 [2] 40 }

  condition:
    any of them
}