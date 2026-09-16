rule TTP_XOR_MULT_DOSStub_498a {
  strings:
    $key_498a = { 1d e2 [2] 69 fa [2] 2e f8 [2] 69 e9 [2] 27 e5 [2] 2b ef [2] 3c e4 [2] 27 aa [2] 1a }

  condition:
    any of them
}