rule TTP_XOR_MULT_DOSStub_3fda {
  strings:
    $key_3fda = { 6b b2 [2] 1f aa [2] 58 a8 [2] 1f b9 [2] 51 b5 [2] 5d bf [2] 4a b4 [2] 51 fa [2] 6c }

  condition:
    any of them
}