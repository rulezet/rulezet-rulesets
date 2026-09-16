rule TTP_XOR_MULT_DOSStub_188a {
  strings:
    $key_188a = { 4c e2 [2] 38 fa [2] 7f f8 [2] 38 e9 [2] 76 e5 [2] 7a ef [2] 6d e4 [2] 76 aa [2] 4b }

  condition:
    any of them
}