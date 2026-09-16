rule TTP_XOR_MULT_DOSStub_848a {
  strings:
    $key_848a = { d0 e2 [2] a4 fa [2] e3 f8 [2] a4 e9 [2] ea e5 [2] e6 ef [2] f1 e4 [2] ea aa [2] d7 }

  condition:
    any of them
}