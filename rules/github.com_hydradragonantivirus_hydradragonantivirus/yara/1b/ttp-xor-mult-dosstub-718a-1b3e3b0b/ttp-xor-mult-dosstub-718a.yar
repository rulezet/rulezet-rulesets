rule TTP_XOR_MULT_DOSStub_718a {
  strings:
    $key_718a = { 25 e2 [2] 51 fa [2] 16 f8 [2] 51 e9 [2] 1f e5 [2] 13 ef [2] 04 e4 [2] 1f aa [2] 22 }

  condition:
    any of them
}