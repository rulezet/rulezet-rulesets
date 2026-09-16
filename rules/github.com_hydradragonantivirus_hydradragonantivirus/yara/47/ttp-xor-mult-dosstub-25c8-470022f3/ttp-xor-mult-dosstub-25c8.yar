rule TTP_XOR_MULT_DOSStub_25c8 {
  strings:
    $key_25c8 = { 71 a0 [2] 05 b8 [2] 42 ba [2] 05 ab [2] 4b a7 [2] 47 ad [2] 50 a6 [2] 4b e8 [2] 76 }

  condition:
    any of them
}