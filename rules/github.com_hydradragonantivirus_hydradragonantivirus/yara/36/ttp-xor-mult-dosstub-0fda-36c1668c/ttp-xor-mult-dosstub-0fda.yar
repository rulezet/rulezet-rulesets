rule TTP_XOR_MULT_DOSStub_0fda {
  strings:
    $key_0fda = { 5b b2 [2] 2f aa [2] 68 a8 [2] 2f b9 [2] 61 b5 [2] 6d bf [2] 7a b4 [2] 61 fa [2] 5c }

  condition:
    any of them
}