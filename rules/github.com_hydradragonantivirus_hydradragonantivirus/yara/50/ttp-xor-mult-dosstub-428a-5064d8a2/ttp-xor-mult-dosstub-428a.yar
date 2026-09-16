rule TTP_XOR_MULT_DOSStub_428a {
  strings:
    $key_428a = { 16 e2 [2] 62 fa [2] 25 f8 [2] 62 e9 [2] 2c e5 [2] 20 ef [2] 37 e4 [2] 2c aa [2] 11 }

  condition:
    any of them
}