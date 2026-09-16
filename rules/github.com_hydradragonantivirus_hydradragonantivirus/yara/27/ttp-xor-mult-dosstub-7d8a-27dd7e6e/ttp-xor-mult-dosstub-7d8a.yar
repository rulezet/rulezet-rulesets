rule TTP_XOR_MULT_DOSStub_7d8a {
  strings:
    $key_7d8a = { 29 e2 [2] 5d fa [2] 1a f8 [2] 5d e9 [2] 13 e5 [2] 1f ef [2] 08 e4 [2] 13 aa [2] 2e }

  condition:
    any of them
}