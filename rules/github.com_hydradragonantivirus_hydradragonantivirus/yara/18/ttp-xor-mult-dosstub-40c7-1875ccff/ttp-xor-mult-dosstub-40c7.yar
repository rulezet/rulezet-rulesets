rule TTP_XOR_MULT_DOSStub_40c7 {
  strings:
    $key_40c7 = { 14 af [2] 60 b7 [2] 27 b5 [2] 60 a4 [2] 2e a8 [2] 22 a2 [2] 35 a9 [2] 2e e7 [2] 13 }

  condition:
    any of them
}