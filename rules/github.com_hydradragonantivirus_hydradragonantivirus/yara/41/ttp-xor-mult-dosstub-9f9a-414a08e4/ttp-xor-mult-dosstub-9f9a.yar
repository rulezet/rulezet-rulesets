rule TTP_XOR_MULT_DOSStub_9f9a {
  strings:
    $key_9f9a = { cb f2 [2] bf ea [2] f8 e8 [2] bf f9 [2] f1 f5 [2] fd ff [2] ea f4 [2] f1 ba [2] cc }

  condition:
    any of them
}