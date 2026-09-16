rule TTP_XOR_MULT_DOSStub_33da {
  strings:
    $key_33da = { 67 b2 [2] 13 aa [2] 54 a8 [2] 13 b9 [2] 5d b5 [2] 51 bf [2] 46 b4 [2] 5d fa [2] 60 }

  condition:
    any of them
}