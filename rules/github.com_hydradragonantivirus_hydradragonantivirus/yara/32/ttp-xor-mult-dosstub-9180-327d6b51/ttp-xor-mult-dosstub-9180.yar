rule TTP_XOR_MULT_DOSStub_9180 {
  strings:
    $key_9180 = { c5 e8 [2] b1 f0 [2] f6 f2 [2] b1 e3 [2] ff ef [2] f3 e5 [2] e4 ee [2] ff a0 [2] c2 }

  condition:
    any of them
}