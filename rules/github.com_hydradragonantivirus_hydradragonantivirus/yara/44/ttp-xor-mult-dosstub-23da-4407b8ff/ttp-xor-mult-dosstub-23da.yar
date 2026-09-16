rule TTP_XOR_MULT_DOSStub_23da {
  strings:
    $key_23da = { 77 b2 [2] 03 aa [2] 44 a8 [2] 03 b9 [2] 4d b5 [2] 41 bf [2] 56 b4 [2] 4d fa [2] 70 }

  condition:
    any of them
}