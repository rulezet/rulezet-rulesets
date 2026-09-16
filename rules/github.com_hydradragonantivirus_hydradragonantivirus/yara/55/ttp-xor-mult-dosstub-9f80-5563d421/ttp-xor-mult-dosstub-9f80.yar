rule TTP_XOR_MULT_DOSStub_9f80 {
  strings:
    $key_9f80 = { cb e8 [2] bf f0 [2] f8 f2 [2] bf e3 [2] f1 ef [2] fd e5 [2] ea ee [2] f1 a0 [2] cc }

  condition:
    any of them
}