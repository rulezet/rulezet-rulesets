rule TTP_XOR_MULT_DOSStub_9f8f {
  strings:
    $key_9f8f = { cb e7 [2] bf ff [2] f8 fd [2] bf ec [2] f1 e0 [2] fd ea [2] ea e1 [2] f1 af [2] cc }

  condition:
    any of them
}