rule TTP_XOR_MULT_DOSStub_638a {
  strings:
    $key_638a = { 37 e2 [2] 43 fa [2] 04 f8 [2] 43 e9 [2] 0d e5 [2] 01 ef [2] 16 e4 [2] 0d aa [2] 30 }

  condition:
    any of them
}