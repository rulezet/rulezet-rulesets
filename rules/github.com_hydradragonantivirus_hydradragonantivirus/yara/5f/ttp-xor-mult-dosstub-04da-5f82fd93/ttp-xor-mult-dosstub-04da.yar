rule TTP_XOR_MULT_DOSStub_04da {
  strings:
    $key_04da = { 50 b2 [2] 24 aa [2] 63 a8 [2] 24 b9 [2] 6a b5 [2] 66 bf [2] 71 b4 [2] 6a fa [2] 57 }

  condition:
    any of them
}