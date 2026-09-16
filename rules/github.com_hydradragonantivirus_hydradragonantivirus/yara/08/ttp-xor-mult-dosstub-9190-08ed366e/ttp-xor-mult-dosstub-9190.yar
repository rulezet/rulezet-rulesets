rule TTP_XOR_MULT_DOSStub_9190 {
  strings:
    $key_9190 = { c5 f8 [2] b1 e0 [2] f6 e2 [2] b1 f3 [2] ff ff [2] f3 f5 [2] e4 fe [2] ff b0 [2] c2 }

  condition:
    any of them
}