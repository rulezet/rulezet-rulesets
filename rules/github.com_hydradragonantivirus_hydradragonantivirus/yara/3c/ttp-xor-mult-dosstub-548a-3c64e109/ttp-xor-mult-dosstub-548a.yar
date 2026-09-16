rule TTP_XOR_MULT_DOSStub_548a {
  strings:
    $key_548a = { 00 e2 [2] 74 fa [2] 33 f8 [2] 74 e9 [2] 3a e5 [2] 36 ef [2] 21 e4 [2] 3a aa [2] 07 }

  condition:
    any of them
}