rule TTP_XOR_MULT_DOSStub_688a {
  strings:
    $key_688a = { 3c e2 [2] 48 fa [2] 0f f8 [2] 48 e9 [2] 06 e5 [2] 0a ef [2] 1d e4 [2] 06 aa [2] 3b }

  condition:
    any of them
}