rule TTP_XOR_MULT_DOSStub_778a {
  strings:
    $key_778a = { 23 e2 [2] 57 fa [2] 10 f8 [2] 57 e9 [2] 19 e5 [2] 15 ef [2] 02 e4 [2] 19 aa [2] 24 }

  condition:
    any of them
}