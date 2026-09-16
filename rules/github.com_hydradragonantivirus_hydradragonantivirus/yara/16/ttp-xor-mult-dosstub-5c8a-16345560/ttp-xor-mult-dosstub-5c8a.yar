rule TTP_XOR_MULT_DOSStub_5c8a {
  strings:
    $key_5c8a = { 08 e2 [2] 7c fa [2] 3b f8 [2] 7c e9 [2] 32 e5 [2] 3e ef [2] 29 e4 [2] 32 aa [2] 0f }

  condition:
    any of them
}