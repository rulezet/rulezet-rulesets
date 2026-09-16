rule TTP_XOR_MULT_DOSStub_2c8a {
  strings:
    $key_2c8a = { 78 e2 [2] 0c fa [2] 4b f8 [2] 0c e9 [2] 42 e5 [2] 4e ef [2] 59 e4 [2] 42 aa [2] 7f }

  condition:
    any of them
}