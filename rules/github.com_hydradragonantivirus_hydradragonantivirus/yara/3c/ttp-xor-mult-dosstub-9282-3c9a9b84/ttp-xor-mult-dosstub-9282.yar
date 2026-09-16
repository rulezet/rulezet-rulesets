rule TTP_XOR_MULT_DOSStub_9282 {
  strings:
    $key_9282 = { c6 ea [2] b2 f2 [2] f5 f0 [2] b2 e1 [2] fc ed [2] f0 e7 [2] e7 ec [2] fc a2 [2] c1 }

  condition:
    any of them
}