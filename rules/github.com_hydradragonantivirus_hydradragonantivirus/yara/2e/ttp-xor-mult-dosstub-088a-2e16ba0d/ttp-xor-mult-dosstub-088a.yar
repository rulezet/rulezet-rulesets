rule TTP_XOR_MULT_DOSStub_088a {
  strings:
    $key_088a = { 5c e2 [2] 28 fa [2] 6f f8 [2] 28 e9 [2] 66 e5 [2] 6a ef [2] 7d e4 [2] 66 aa [2] 5b }

  condition:
    any of them
}