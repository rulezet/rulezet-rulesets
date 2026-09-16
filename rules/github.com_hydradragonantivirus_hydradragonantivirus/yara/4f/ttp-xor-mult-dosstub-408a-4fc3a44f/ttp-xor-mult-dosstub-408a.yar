rule TTP_XOR_MULT_DOSStub_408a {
  strings:
    $key_408a = { 14 e2 [2] 60 fa [2] 27 f8 [2] 60 e9 [2] 2e e5 [2] 22 ef [2] 35 e4 [2] 2e aa [2] 13 }

  condition:
    any of them
}