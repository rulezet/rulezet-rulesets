rule TTP_XOR_MULT_DOSStub_8f8a {
  strings:
    $key_8f8a = { db e2 [2] af fa [2] e8 f8 [2] af e9 [2] e1 e5 [2] ed ef [2] fa e4 [2] e1 aa [2] dc }

  condition:
    any of them
}