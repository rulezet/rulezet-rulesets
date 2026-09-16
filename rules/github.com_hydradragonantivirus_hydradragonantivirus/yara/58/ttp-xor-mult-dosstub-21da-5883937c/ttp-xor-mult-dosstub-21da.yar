rule TTP_XOR_MULT_DOSStub_21da {
  strings:
    $key_21da = { 75 b2 [2] 01 aa [2] 46 a8 [2] 01 b9 [2] 4f b5 [2] 43 bf [2] 54 b4 [2] 4f fa [2] 72 }

  condition:
    any of them
}