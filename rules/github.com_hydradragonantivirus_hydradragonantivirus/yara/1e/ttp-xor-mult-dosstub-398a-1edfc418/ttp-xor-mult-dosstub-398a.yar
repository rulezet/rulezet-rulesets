rule TTP_XOR_MULT_DOSStub_398a {
  strings:
    $key_398a = { 6d e2 [2] 19 fa [2] 5e f8 [2] 19 e9 [2] 57 e5 [2] 5b ef [2] 4c e4 [2] 57 aa [2] 6a }

  condition:
    any of them
}