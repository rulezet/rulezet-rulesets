rule TTP_XOR_MULT_DOSStub_a38a {
  strings:
    $key_a38a = { f7 e2 [2] 83 fa [2] c4 f8 [2] 83 e9 [2] cd e5 [2] c1 ef [2] d6 e4 [2] cd aa [2] f0 }

  condition:
    any of them
}