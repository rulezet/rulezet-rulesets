rule TTP_XOR_MULT_DOSStub_9284 {
  strings:
    $key_9284 = { c6 ec [2] b2 f4 [2] f5 f6 [2] b2 e7 [2] fc eb [2] f0 e1 [2] e7 ea [2] fc a4 [2] c1 }

  condition:
    any of them
}