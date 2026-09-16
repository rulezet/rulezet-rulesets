rule TTP_XOR_MULT_DOSStub_33c7 {
  strings:
    $key_33c7 = { 67 af [2] 13 b7 [2] 54 b5 [2] 13 a4 [2] 5d a8 [2] 51 a2 [2] 46 a9 [2] 5d e7 [2] 60 }

  condition:
    any of them
}