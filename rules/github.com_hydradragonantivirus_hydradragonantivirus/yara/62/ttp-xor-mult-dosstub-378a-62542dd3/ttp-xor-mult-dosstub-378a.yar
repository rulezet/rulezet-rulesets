rule TTP_XOR_MULT_DOSStub_378a {
  strings:
    $key_378a = { 63 e2 [2] 17 fa [2] 50 f8 [2] 17 e9 [2] 59 e5 [2] 55 ef [2] 42 e4 [2] 59 aa [2] 64 }

  condition:
    any of them
}