rule TTP_XOR_MULT_DOSStub_e28a {
  strings:
    $key_e28a = { b6 e2 [2] c2 fa [2] 85 f8 [2] c2 e9 [2] 8c e5 [2] 80 ef [2] 97 e4 [2] 8c aa [2] b1 }

  condition:
    any of them
}