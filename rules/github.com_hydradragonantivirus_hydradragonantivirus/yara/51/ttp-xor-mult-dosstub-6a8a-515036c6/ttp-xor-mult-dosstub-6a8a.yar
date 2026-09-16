rule TTP_XOR_MULT_DOSStub_6a8a {
  strings:
    $key_6a8a = { 3e e2 [2] 4a fa [2] 0d f8 [2] 4a e9 [2] 04 e5 [2] 08 ef [2] 1f e4 [2] 04 aa [2] 39 }

  condition:
    any of them
}