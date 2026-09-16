rule TTP_XOR_MULT_DOSStub_b0da {
  strings:
    $key_b0da = { e4 b2 [2] 90 aa [2] d7 a8 [2] 90 b9 [2] de b5 [2] d2 bf [2] c5 b4 [2] de fa [2] e3 }

  condition:
    any of them
}