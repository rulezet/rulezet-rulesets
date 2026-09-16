rule TTP_XOR_MULT_DOSStub_00c7 {
  strings:
    $key_00c7 = { 54 af [2] 20 b7 [2] 67 b5 [2] 20 a4 [2] 6e a8 [2] 62 a2 [2] 75 a9 [2] 6e e7 [2] 53 }

  condition:
    any of them
}