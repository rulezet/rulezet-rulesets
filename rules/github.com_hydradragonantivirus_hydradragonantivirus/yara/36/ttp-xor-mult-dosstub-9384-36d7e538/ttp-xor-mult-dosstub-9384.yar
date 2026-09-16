rule TTP_XOR_MULT_DOSStub_9384 {
  strings:
    $key_9384 = { c7 ec [2] b3 f4 [2] f4 f6 [2] b3 e7 [2] fd eb [2] f1 e1 [2] e6 ea [2] fd a4 [2] c0 }

  condition:
    any of them
}