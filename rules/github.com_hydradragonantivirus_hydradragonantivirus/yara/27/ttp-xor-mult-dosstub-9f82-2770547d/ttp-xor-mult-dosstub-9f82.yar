rule TTP_XOR_MULT_DOSStub_9f82 {
  strings:
    $key_9f82 = { cb ea [2] bf f2 [2] f8 f0 [2] bf e1 [2] f1 ed [2] fd e7 [2] ea ec [2] f1 a2 [2] cc }

  condition:
    any of them
}