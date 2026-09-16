rule TTP_XOR_MULT_DOSStub_d58a {
  strings:
    $key_d58a = { 81 e2 [2] f5 fa [2] b2 f8 [2] f5 e9 [2] bb e5 [2] b7 ef [2] a0 e4 [2] bb aa [2] 86 }

  condition:
    any of them
}