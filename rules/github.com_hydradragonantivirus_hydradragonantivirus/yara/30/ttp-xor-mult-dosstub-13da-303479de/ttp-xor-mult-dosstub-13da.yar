rule TTP_XOR_MULT_DOSStub_13da {
  strings:
    $key_13da = { 47 b2 [2] 33 aa [2] 74 a8 [2] 33 b9 [2] 7d b5 [2] 71 bf [2] 66 b4 [2] 7d fa [2] 40 }

  condition:
    any of them
}