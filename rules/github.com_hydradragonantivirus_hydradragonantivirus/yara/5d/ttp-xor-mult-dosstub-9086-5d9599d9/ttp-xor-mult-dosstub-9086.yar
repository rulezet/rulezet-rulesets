rule TTP_XOR_MULT_DOSStub_9086 {
  strings:
    $key_9086 = { c4 ee [2] b0 f6 [2] f7 f4 [2] b0 e5 [2] fe e9 [2] f2 e3 [2] e5 e8 [2] fe a6 [2] c3 }

  condition:
    any of them
}