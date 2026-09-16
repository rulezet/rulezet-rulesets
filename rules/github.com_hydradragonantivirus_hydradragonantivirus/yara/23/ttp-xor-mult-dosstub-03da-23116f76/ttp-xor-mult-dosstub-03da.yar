rule TTP_XOR_MULT_DOSStub_03da {
  strings:
    $key_03da = { 57 b2 [2] 23 aa [2] 64 a8 [2] 23 b9 [2] 6d b5 [2] 61 bf [2] 76 b4 [2] 6d fa [2] 50 }

  condition:
    any of them
}