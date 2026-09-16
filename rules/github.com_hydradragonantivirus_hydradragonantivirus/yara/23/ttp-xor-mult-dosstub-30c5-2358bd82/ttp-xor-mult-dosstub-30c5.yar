rule TTP_XOR_MULT_DOSStub_30c5 {
  strings:
    $key_30c5 = { 64 ad [2] 10 b5 [2] 57 b7 [2] 10 a6 [2] 5e aa [2] 52 a0 [2] 45 ab [2] 5e e5 [2] 63 }

  condition:
    any of them
}