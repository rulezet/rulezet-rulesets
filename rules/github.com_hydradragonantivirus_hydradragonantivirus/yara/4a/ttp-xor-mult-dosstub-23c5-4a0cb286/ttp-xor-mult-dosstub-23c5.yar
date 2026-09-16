rule TTP_XOR_MULT_DOSStub_23c5 {
  strings:
    $key_23c5 = { 77 ad [2] 03 b5 [2] 44 b7 [2] 03 a6 [2] 4d aa [2] 41 a0 [2] 56 ab [2] 4d e5 [2] 70 }

  condition:
    any of them
}