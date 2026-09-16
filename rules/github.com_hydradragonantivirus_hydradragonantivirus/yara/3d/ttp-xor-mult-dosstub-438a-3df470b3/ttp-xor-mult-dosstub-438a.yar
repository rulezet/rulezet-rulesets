rule TTP_XOR_MULT_DOSStub_438a {
  strings:
    $key_438a = { 17 e2 [2] 63 fa [2] 24 f8 [2] 63 e9 [2] 2d e5 [2] 21 ef [2] 36 e4 [2] 2d aa [2] 10 }

  condition:
    any of them
}