rule TTP_XOR_MULT_DOSStub_0c8a {
  strings:
    $key_0c8a = { 58 e2 [2] 2c fa [2] 6b f8 [2] 2c e9 [2] 62 e5 [2] 6e ef [2] 79 e4 [2] 62 aa [2] 5f }

  condition:
    any of them
}