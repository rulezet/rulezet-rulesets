rule TTP_XOR_MULT_DOSStub_33d7 {
  strings:
    $key_33d7 = { 67 bf [2] 13 a7 [2] 54 a5 [2] 13 b4 [2] 5d b8 [2] 51 b2 [2] 46 b9 [2] 5d f7 [2] 60 }

  condition:
    any of them
}