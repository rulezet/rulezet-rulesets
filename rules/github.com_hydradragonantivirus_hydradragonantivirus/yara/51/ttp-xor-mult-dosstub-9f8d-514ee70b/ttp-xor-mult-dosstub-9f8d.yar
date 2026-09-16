rule TTP_XOR_MULT_DOSStub_9f8d {
  strings:
    $key_9f8d = { cb e5 [2] bf fd [2] f8 ff [2] bf ee [2] f1 e2 [2] fd e8 [2] ea e3 [2] f1 ad [2] cc }

  condition:
    any of them
}