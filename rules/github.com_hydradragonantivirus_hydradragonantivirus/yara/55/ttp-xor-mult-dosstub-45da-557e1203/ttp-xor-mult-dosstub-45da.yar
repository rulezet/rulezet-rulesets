rule TTP_XOR_MULT_DOSStub_45da {
  strings:
    $key_45da = { 11 b2 [2] 65 aa [2] 22 a8 [2] 65 b9 [2] 2b b5 [2] 27 bf [2] 30 b4 [2] 2b fa [2] 16 }

  condition:
    any of them
}