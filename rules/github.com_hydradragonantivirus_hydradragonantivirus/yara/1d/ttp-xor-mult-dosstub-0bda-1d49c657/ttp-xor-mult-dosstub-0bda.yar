rule TTP_XOR_MULT_DOSStub_0bda {
  strings:
    $key_0bda = { 5f b2 [2] 2b aa [2] 6c a8 [2] 2b b9 [2] 65 b5 [2] 69 bf [2] 7e b4 [2] 65 fa [2] 58 }

  condition:
    any of them
}