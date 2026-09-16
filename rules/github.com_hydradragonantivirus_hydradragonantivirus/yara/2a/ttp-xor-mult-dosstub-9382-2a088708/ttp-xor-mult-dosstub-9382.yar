rule TTP_XOR_MULT_DOSStub_9382 {
  strings:
    $key_9382 = { c7 ea [2] b3 f2 [2] f4 f0 [2] b3 e1 [2] fd ed [2] f1 e7 [2] e6 ec [2] fd a2 [2] c0 }

  condition:
    any of them
}