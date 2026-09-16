rule TTP_XOR_MULT_DOSStub_01da {
  strings:
    $key_01da = { 55 b2 [2] 21 aa [2] 66 a8 [2] 21 b9 [2] 6f b5 [2] 63 bf [2] 74 b4 [2] 6f fa [2] 52 }

  condition:
    any of them
}