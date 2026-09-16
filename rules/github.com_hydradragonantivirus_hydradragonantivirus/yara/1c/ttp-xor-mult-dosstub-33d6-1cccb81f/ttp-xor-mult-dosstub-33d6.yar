rule TTP_XOR_MULT_DOSStub_33d6 {
  strings:
    $key_33d6 = { 67 be [2] 13 a6 [2] 54 a4 [2] 13 b5 [2] 5d b9 [2] 51 b3 [2] 46 b8 [2] 5d f6 [2] 60 }

  condition:
    any of them
}