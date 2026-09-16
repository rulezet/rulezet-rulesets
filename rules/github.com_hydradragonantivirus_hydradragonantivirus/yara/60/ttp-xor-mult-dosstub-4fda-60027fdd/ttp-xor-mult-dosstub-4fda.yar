rule TTP_XOR_MULT_DOSStub_4fda {
  strings:
    $key_4fda = { 1b b2 [2] 6f aa [2] 28 a8 [2] 6f b9 [2] 21 b5 [2] 2d bf [2] 3a b4 [2] 21 fa [2] 1c }

  condition:
    any of them
}