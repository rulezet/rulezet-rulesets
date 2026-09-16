rule TTP_XOR_MULT_DOSStub_4c8a {
  strings:
    $key_4c8a = { 18 e2 [2] 6c fa [2] 2b f8 [2] 6c e9 [2] 22 e5 [2] 2e ef [2] 39 e4 [2] 22 aa [2] 1f }

  condition:
    any of them
}