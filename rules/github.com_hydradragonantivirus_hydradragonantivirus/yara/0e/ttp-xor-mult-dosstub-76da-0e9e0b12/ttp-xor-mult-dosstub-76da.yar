rule TTP_XOR_MULT_DOSStub_76da {
  strings:
    $key_76da = { 22 b2 [2] 56 aa [2] 11 a8 [2] 56 b9 [2] 18 b5 [2] 14 bf [2] 03 b4 [2] 18 fa [2] 25 }

  condition:
    any of them
}