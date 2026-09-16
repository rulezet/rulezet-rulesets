rule TTP_XOR_MULT_DOSStub_9687 {
  strings:
    $key_9687 = { c2 ef [2] b6 f7 [2] f1 f5 [2] b6 e4 [2] f8 e8 [2] f4 e2 [2] e3 e9 [2] f8 a7 [2] c5 }

  condition:
    any of them
}