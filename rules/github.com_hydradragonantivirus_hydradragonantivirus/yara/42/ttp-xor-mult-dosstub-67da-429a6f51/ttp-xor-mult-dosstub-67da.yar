rule TTP_XOR_MULT_DOSStub_67da {
  strings:
    $key_67da = { 33 b2 [2] 47 aa [2] 00 a8 [2] 47 b9 [2] 09 b5 [2] 05 bf [2] 12 b4 [2] 09 fa [2] 34 }

  condition:
    any of them
}