rule TTP_XOR_MULT_DOSStub_2a8a {
  strings:
    $key_2a8a = { 7e e2 [2] 0a fa [2] 4d f8 [2] 0a e9 [2] 44 e5 [2] 48 ef [2] 5f e4 [2] 44 aa [2] 79 }

  condition:
    any of them
}