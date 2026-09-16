rule TTP_XOR_MULT_DOSStub_50c8 {
  strings:
    $key_50c8 = { 04 a0 [2] 70 b8 [2] 37 ba [2] 70 ab [2] 3e a7 [2] 32 ad [2] 25 a6 [2] 3e e8 [2] 03 }

  condition:
    any of them
}