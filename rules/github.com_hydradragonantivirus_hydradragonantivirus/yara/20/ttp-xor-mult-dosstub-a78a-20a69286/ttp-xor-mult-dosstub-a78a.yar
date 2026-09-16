rule TTP_XOR_MULT_DOSStub_a78a {
  strings:
    $key_a78a = { f3 e2 [2] 87 fa [2] c0 f8 [2] 87 e9 [2] c9 e5 [2] c5 ef [2] d2 e4 [2] c9 aa [2] f4 }

  condition:
    any of them
}