rule TTP_XOR_MULT_DOSStub_2fda {
  strings:
    $key_2fda = { 7b b2 [2] 0f aa [2] 48 a8 [2] 0f b9 [2] 41 b5 [2] 4d bf [2] 5a b4 [2] 41 fa [2] 7c }

  condition:
    any of them
}