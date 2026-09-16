rule TTP_XOR_MULT_DOSStub_9b8a {
  strings:
    $key_9b8a = { cf e2 [2] bb fa [2] fc f8 [2] bb e9 [2] f5 e5 [2] f9 ef [2] ee e4 [2] f5 aa [2] c8 }

  condition:
    any of them
}