rule TTP_XOR_MULT_DOSStub_4bda {
  strings:
    $key_4bda = { 1f b2 [2] 6b aa [2] 2c a8 [2] 6b b9 [2] 25 b5 [2] 29 bf [2] 3e b4 [2] 25 fa [2] 18 }

  condition:
    any of them
}