rule TTP_XOR_MULT_DOSStub_a18a {
  strings:
    $key_a18a = { f5 e2 [2] 81 fa [2] c6 f8 [2] 81 e9 [2] cf e5 [2] c3 ef [2] d4 e4 [2] cf aa [2] f2 }

  condition:
    any of them
}