rule TTP_XOR_MULT_DOSStub_038a {
  strings:
    $key_038a = { 57 e2 [2] 23 fa [2] 64 f8 [2] 23 e9 [2] 6d e5 [2] 61 ef [2] 76 e4 [2] 6d aa [2] 50 }

  condition:
    any of them
}