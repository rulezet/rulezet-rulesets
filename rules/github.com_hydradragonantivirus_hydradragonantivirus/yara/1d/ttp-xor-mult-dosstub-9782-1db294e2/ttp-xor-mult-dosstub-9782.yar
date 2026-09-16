rule TTP_XOR_MULT_DOSStub_9782 {
  strings:
    $key_9782 = { c3 ea [2] b7 f2 [2] f0 f0 [2] b7 e1 [2] f9 ed [2] f5 e7 [2] e2 ec [2] f9 a2 [2] c4 }

  condition:
    any of them
}