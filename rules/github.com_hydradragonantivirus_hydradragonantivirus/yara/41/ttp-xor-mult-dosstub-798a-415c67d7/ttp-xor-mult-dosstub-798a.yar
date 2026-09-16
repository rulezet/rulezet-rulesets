rule TTP_XOR_MULT_DOSStub_798a {
  strings:
    $key_798a = { 2d e2 [2] 59 fa [2] 1e f8 [2] 59 e9 [2] 17 e5 [2] 1b ef [2] 0c e4 [2] 17 aa [2] 2a }

  condition:
    any of them
}