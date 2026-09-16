rule TTP_XOR_MULT_DOSStub_198a {
  strings:
    $key_198a = { 4d e2 [2] 39 fa [2] 7e f8 [2] 39 e9 [2] 77 e5 [2] 7b ef [2] 6c e4 [2] 77 aa [2] 4a }

  condition:
    any of them
}