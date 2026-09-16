rule TTP_XOR_MULT_DOSStub_978a {
  strings:
    $key_978a = { c3 e2 [2] b7 fa [2] f0 f8 [2] b7 e9 [2] f9 e5 [2] f5 ef [2] e2 e4 [2] f9 aa [2] c4 }

  condition:
    any of them
}