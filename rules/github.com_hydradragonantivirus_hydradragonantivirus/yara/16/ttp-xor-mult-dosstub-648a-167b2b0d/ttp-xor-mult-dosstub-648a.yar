rule TTP_XOR_MULT_DOSStub_648a {
  strings:
    $key_648a = { 30 e2 [2] 44 fa [2] 03 f8 [2] 44 e9 [2] 0a e5 [2] 06 ef [2] 11 e4 [2] 0a aa [2] 37 }

  condition:
    any of them
}