rule TTP_XOR_MULT_DOSStub_708a {
  strings:
    $key_708a = { 24 e2 [2] 50 fa [2] 17 f8 [2] 50 e9 [2] 1e e5 [2] 12 ef [2] 05 e4 [2] 1e aa [2] 23 }

  condition:
    any of them
}