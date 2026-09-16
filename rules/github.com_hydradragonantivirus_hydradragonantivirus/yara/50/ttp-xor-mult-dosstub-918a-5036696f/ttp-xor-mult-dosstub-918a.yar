rule TTP_XOR_MULT_DOSStub_918a {
  strings:
    $key_918a = { c5 e2 [2] b1 fa [2] f6 f8 [2] b1 e9 [2] ff e5 [2] f3 ef [2] e4 e4 [2] ff aa [2] c2 }

  condition:
    any of them
}