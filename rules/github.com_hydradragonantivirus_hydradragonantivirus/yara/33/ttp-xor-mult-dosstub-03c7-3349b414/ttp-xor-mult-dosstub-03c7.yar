rule TTP_XOR_MULT_DOSStub_03c7 {
  strings:
    $key_03c7 = { 57 af [2] 23 b7 [2] 64 b5 [2] 23 a4 [2] 6d a8 [2] 61 a2 [2] 76 a9 [2] 6d e7 [2] 50 }

  condition:
    any of them
}