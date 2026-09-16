rule TTP_XOR_MULT_DOSStub_9287 {
  strings:
    $key_9287 = { c6 ef [2] b2 f7 [2] f5 f5 [2] b2 e4 [2] fc e8 [2] f0 e2 [2] e7 e9 [2] fc a7 [2] c1 }

  condition:
    any of them
}