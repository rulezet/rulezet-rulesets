rule TTP_XOR_MULT_DOSStub_9f9b {
  strings:
    $key_9f9b = { cb f3 [2] bf eb [2] f8 e9 [2] bf f8 [2] f1 f4 [2] fd fe [2] ea f5 [2] f1 bb [2] cc }

  condition:
    any of them
}