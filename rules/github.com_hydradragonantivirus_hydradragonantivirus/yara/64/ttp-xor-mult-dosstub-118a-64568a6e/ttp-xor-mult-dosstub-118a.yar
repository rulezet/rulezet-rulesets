rule TTP_XOR_MULT_DOSStub_118a {
  strings:
    $key_118a = { 45 e2 [2] 31 fa [2] 76 f8 [2] 31 e9 [2] 7f e5 [2] 73 ef [2] 64 e4 [2] 7f aa [2] 42 }

  condition:
    any of them
}