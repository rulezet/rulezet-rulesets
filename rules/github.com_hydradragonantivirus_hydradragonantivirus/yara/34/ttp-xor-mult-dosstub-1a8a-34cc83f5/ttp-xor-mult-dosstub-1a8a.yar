rule TTP_XOR_MULT_DOSStub_1a8a {
  strings:
    $key_1a8a = { 4e e2 [2] 3a fa [2] 7d f8 [2] 3a e9 [2] 74 e5 [2] 78 ef [2] 6f e4 [2] 74 aa [2] 49 }

  condition:
    any of them
}