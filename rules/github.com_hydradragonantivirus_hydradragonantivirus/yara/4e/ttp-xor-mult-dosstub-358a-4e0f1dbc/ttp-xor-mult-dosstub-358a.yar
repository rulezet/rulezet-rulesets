rule TTP_XOR_MULT_DOSStub_358a {
  strings:
    $key_358a = { 61 e2 [2] 15 fa [2] 52 f8 [2] 15 e9 [2] 5b e5 [2] 57 ef [2] 40 e4 [2] 5b aa [2] 66 }

  condition:
    any of them
}