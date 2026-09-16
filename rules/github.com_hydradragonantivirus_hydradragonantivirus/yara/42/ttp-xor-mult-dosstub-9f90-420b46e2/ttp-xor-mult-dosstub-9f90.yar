rule TTP_XOR_MULT_DOSStub_9f90 {
  strings:
    $key_9f90 = { cb f8 [2] bf e0 [2] f8 e2 [2] bf f3 [2] f1 ff [2] fd f5 [2] ea fe [2] f1 b0 [2] cc }

  condition:
    any of them
}