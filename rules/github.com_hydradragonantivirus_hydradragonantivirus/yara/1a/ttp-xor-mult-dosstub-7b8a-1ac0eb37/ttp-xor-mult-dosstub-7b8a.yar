rule TTP_XOR_MULT_DOSStub_7b8a {
  strings:
    $key_7b8a = { 2f e2 [2] 5b fa [2] 1c f8 [2] 5b e9 [2] 15 e5 [2] 19 ef [2] 0e e4 [2] 15 aa [2] 28 }

  condition:
    any of them
}