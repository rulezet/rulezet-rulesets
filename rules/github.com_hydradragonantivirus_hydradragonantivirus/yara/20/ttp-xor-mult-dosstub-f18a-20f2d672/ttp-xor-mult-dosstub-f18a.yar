rule TTP_XOR_MULT_DOSStub_f18a {
  strings:
    $key_f18a = { a5 e2 [2] d1 fa [2] 96 f8 [2] d1 e9 [2] 9f e5 [2] 93 ef [2] 84 e4 [2] 9f aa [2] a2 }

  condition:
    any of them
}