rule TTP_XOR_MULT_DOSStub_7ada {
  strings:
    $key_7ada = { 2e b2 [2] 5a aa [2] 1d a8 [2] 5a b9 [2] 14 b5 [2] 18 bf [2] 0f b4 [2] 14 fa [2] 29 }

  condition:
    any of them
}