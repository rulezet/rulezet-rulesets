rule TTP_XOR_MULT_DOSStub_a58a {
  strings:
    $key_a58a = { f1 e2 [2] 85 fa [2] c2 f8 [2] 85 e9 [2] cb e5 [2] c7 ef [2] d0 e4 [2] cb aa [2] f6 }

  condition:
    any of them
}