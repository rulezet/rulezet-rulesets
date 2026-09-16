rule TTP_XOR_MULT_DOSStub_128a {
  strings:
    $key_128a = { 46 e2 [2] 32 fa [2] 75 f8 [2] 32 e9 [2] 7c e5 [2] 70 ef [2] 67 e4 [2] 7c aa [2] 41 }

  condition:
    any of them
}