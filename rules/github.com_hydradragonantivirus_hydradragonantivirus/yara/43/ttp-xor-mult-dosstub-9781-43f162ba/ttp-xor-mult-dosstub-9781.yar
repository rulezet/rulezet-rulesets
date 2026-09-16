rule TTP_XOR_MULT_DOSStub_9781 {
  strings:
    $key_9781 = { c3 e9 [2] b7 f1 [2] f0 f3 [2] b7 e2 [2] f9 ee [2] f5 e4 [2] e2 ef [2] f9 a1 [2] c4 }

  condition:
    any of them
}