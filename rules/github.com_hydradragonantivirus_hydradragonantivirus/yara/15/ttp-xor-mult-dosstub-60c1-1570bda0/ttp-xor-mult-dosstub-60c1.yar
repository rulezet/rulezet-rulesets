rule TTP_XOR_MULT_DOSStub_60c1 {
  strings:
    $key_60c1 = { 34 a9 [2] 40 b1 [2] 07 b3 [2] 40 a2 [2] 0e ae [2] 02 a4 [2] 15 af [2] 0e e1 [2] 33 }

  condition:
    any of them
}