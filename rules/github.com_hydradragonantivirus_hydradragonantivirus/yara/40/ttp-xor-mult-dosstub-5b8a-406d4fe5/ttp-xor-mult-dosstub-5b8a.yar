rule TTP_XOR_MULT_DOSStub_5b8a {
  strings:
    $key_5b8a = { 0f e2 [2] 7b fa [2] 3c f8 [2] 7b e9 [2] 35 e5 [2] 39 ef [2] 2e e4 [2] 35 aa [2] 08 }

  condition:
    any of them
}