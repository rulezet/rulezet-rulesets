rule TTP_XOR_MULT_DOSStub_9387 {
  strings:
    $key_9387 = { c7 ef [2] b3 f7 [2] f4 f5 [2] b3 e4 [2] fd e8 [2] f1 e2 [2] e6 e9 [2] fd a7 [2] c0 }

  condition:
    any of them
}