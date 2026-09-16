rule TTP_XOR_MULT_DOSStub_9189 {
  strings:
    $key_9189 = { c5 e1 [2] b1 f9 [2] f6 fb [2] b1 ea [2] ff e6 [2] f3 ec [2] e4 e7 [2] ff a9 [2] c2 }

  condition:
    any of them
}