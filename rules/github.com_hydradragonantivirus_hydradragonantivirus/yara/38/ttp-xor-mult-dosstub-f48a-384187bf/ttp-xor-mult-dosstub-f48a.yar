rule TTP_XOR_MULT_DOSStub_f48a {
  strings:
    $key_f48a = { a0 e2 [2] d4 fa [2] 93 f8 [2] d4 e9 [2] 9a e5 [2] 96 ef [2] 81 e4 [2] 9a aa [2] a7 }

  condition:
    any of them
}