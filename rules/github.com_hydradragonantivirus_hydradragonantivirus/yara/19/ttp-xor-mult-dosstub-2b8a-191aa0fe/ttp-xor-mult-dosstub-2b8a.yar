rule TTP_XOR_MULT_DOSStub_2b8a {
  strings:
    $key_2b8a = { 7f e2 [2] 0b fa [2] 4c f8 [2] 0b e9 [2] 45 e5 [2] 49 ef [2] 5e e4 [2] 45 aa [2] 78 }

  condition:
    any of them
}