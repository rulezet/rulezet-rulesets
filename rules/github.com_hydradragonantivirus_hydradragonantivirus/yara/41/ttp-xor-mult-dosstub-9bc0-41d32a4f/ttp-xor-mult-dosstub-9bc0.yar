rule TTP_XOR_MULT_DOSStub_9bc0 {
  strings:
    $key_9bc0 = { cf a8 [2] bb b0 [2] fc b2 [2] bb a3 [2] f5 af [2] f9 a5 [2] ee ae [2] f5 e0 [2] c8 }

  condition:
    any of them
}