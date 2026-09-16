rule TTP_XOR_MULT_DOSStub_098a {
  strings:
    $key_098a = { 5d e2 [2] 29 fa [2] 6e f8 [2] 29 e9 [2] 67 e5 [2] 6b ef [2] 7c e4 [2] 67 aa [2] 5a }

  condition:
    any of them
}