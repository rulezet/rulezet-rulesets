rule TTP_XOR_MULT_DOSStub_9786 {
  strings:
    $key_9786 = { c3 ee [2] b7 f6 [2] f0 f4 [2] b7 e5 [2] f9 e9 [2] f5 e3 [2] e2 e8 [2] f9 a6 [2] c4 }

  condition:
    any of them
}