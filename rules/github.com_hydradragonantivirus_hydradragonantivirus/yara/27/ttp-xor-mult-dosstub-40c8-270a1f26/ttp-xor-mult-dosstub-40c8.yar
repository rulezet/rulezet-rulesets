rule TTP_XOR_MULT_DOSStub_40c8 {
  strings:
    $key_40c8 = { 14 a0 [2] 60 b8 [2] 27 ba [2] 60 ab [2] 2e a7 [2] 22 ad [2] 35 a6 [2] 2e e8 [2] 13 }

  condition:
    any of them
}