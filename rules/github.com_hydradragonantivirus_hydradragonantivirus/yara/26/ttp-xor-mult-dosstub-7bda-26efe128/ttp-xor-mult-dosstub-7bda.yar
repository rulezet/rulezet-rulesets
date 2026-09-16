rule TTP_XOR_MULT_DOSStub_7bda {
  strings:
    $key_7bda = { 2f b2 [2] 5b aa [2] 1c a8 [2] 5b b9 [2] 15 b5 [2] 19 bf [2] 0e b4 [2] 15 fa [2] 28 }

  condition:
    any of them
}