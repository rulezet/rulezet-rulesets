rule TTP_XOR_MULT_DOSStub_9f96 {
  strings:
    $key_9f96 = { cb fe [2] bf e6 [2] f8 e4 [2] bf f5 [2] f1 f9 [2] fd f3 [2] ea f8 [2] f1 b6 [2] cc }

  condition:
    any of them
}