rule TTP_XOR_MULT_DOSStub_9f85 {
  strings:
    $key_9f85 = { cb ed [2] bf f5 [2] f8 f7 [2] bf e6 [2] f1 ea [2] fd e0 [2] ea eb [2] f1 a5 [2] cc }

  condition:
    any of them
}