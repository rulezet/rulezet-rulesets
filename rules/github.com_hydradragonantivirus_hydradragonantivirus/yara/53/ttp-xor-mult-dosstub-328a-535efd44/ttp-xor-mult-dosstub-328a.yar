rule TTP_XOR_MULT_DOSStub_328a {
  strings:
    $key_328a = { 66 e2 [2] 12 fa [2] 55 f8 [2] 12 e9 [2] 5c e5 [2] 50 ef [2] 47 e4 [2] 5c aa [2] 61 }

  condition:
    any of them
}