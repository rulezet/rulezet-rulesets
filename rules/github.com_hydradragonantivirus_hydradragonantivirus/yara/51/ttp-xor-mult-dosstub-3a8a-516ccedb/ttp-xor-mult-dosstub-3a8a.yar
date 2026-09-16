rule TTP_XOR_MULT_DOSStub_3a8a {
  strings:
    $key_3a8a = { 6e e2 [2] 1a fa [2] 5d f8 [2] 1a e9 [2] 54 e5 [2] 58 ef [2] 4f e4 [2] 54 aa [2] 69 }

  condition:
    any of them
}