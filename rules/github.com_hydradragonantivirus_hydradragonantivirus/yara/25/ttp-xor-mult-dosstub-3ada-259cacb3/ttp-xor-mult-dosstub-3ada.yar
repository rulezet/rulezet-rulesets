rule TTP_XOR_MULT_DOSStub_3ada {
  strings:
    $key_3ada = { 6e b2 [2] 1a aa [2] 5d a8 [2] 1a b9 [2] 54 b5 [2] 58 bf [2] 4f b4 [2] 54 fa [2] 69 }

  condition:
    any of them
}