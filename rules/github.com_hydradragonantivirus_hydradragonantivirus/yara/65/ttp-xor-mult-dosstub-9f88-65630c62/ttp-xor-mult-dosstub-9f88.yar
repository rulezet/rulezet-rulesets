rule TTP_XOR_MULT_DOSStub_9f88 {
  strings:
    $key_9f88 = { cb e0 [2] bf f8 [2] f8 fa [2] bf eb [2] f1 e7 [2] fd ed [2] ea e6 [2] f1 a8 [2] cc }

  condition:
    any of them
}