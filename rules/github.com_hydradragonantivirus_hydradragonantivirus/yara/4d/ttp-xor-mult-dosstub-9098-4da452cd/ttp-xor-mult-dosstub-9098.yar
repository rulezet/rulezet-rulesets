rule TTP_XOR_MULT_DOSStub_9098 {
  strings:
    $key_9098 = { c4 f0 [2] b0 e8 [2] f7 ea [2] b0 fb [2] fe f7 [2] f2 fd [2] e5 f6 [2] fe b8 [2] c3 }

  condition:
    any of them
}