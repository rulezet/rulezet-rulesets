rule TTP_XOR_MULT_DOSStub_9f84 {
  strings:
    $key_9f84 = { cb ec [2] bf f4 [2] f8 f6 [2] bf e7 [2] f1 eb [2] fd e1 [2] ea ea [2] f1 a4 [2] cc }

  condition:
    any of them
}