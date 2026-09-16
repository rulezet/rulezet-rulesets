rule TTP_XOR_MULT_DOSStub_138a {
  strings:
    $key_138a = { 47 e2 [2] 33 fa [2] 74 f8 [2] 33 e9 [2] 7d e5 [2] 71 ef [2] 66 e4 [2] 7d aa [2] 40 }

  condition:
    any of them
}