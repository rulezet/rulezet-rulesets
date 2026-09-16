rule TTP_XOR_MULT_DOSStub_63c7 {
  strings:
    $key_63c7 = { 37 af [2] 43 b7 [2] 04 b5 [2] 43 a4 [2] 0d a8 [2] 01 a2 [2] 16 a9 [2] 0d e7 [2] 30 }

  condition:
    any of them
}