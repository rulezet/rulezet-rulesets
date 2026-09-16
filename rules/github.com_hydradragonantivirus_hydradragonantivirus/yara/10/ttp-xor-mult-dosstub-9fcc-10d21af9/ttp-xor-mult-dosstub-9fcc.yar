rule TTP_XOR_MULT_DOSStub_9fcc {
  strings:
    $key_9fcc = { cb a4 [2] bf bc [2] f8 be [2] bf af [2] f1 a3 [2] fd a9 [2] ea a2 [2] f1 ec [2] cc }

  condition:
    any of them
}