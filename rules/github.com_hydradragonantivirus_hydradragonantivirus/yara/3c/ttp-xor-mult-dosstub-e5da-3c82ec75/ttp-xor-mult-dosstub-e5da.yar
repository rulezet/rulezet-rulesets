rule TTP_XOR_MULT_DOSStub_e5da {
  strings:
    $key_e5da = { b1 b2 [2] c5 aa [2] 82 a8 [2] c5 b9 [2] 8b b5 [2] 87 bf [2] 90 b4 [2] 8b fa [2] b6 }

  condition:
    any of them
}