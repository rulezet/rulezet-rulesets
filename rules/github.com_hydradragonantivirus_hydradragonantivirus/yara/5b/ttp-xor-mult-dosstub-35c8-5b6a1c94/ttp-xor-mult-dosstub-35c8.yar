rule TTP_XOR_MULT_DOSStub_35c8 {
  strings:
    $key_35c8 = { 61 a0 [2] 15 b8 [2] 52 ba [2] 15 ab [2] 5b a7 [2] 57 ad [2] 40 a6 [2] 5b e8 [2] 66 }

  condition:
    any of them
}