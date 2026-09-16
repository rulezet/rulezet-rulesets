rule TTP_XOR_MULT_DOSStub_70da {
  strings:
    $key_70da = { 24 b2 [2] 50 aa [2] 17 a8 [2] 50 b9 [2] 1e b5 [2] 12 bf [2] 05 b4 [2] 1e fa [2] 23 }

  condition:
    any of them
}