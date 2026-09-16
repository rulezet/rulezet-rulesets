rule TTP_XOR_MULT_DOSStub_60c8 {
  strings:
    $key_60c8 = { 34 a0 [2] 40 b8 [2] 07 ba [2] 40 ab [2] 0e a7 [2] 02 ad [2] 15 a6 [2] 0e e8 [2] 33 }

  condition:
    any of them
}