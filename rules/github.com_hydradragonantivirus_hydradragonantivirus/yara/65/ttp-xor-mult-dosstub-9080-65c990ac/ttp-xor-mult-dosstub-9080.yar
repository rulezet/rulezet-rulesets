rule TTP_XOR_MULT_DOSStub_9080 {
  strings:
    $key_9080 = { c4 e8 [2] b0 f0 [2] f7 f2 [2] b0 e3 [2] fe ef [2] f2 e5 [2] e5 ee [2] fe a0 [2] c3 }

  condition:
    any of them
}