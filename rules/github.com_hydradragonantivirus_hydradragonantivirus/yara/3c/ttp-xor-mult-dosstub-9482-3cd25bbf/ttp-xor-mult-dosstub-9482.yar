rule TTP_XOR_MULT_DOSStub_9482 {
  strings:
    $key_9482 = { c0 ea [2] b4 f2 [2] f3 f0 [2] b4 e1 [2] fa ed [2] f6 e7 [2] e1 ec [2] fa a2 [2] c7 }

  condition:
    any of them
}