rule TTP_XOR_MULT_DOSStub_9f9f {
  strings:
    $key_9f9f = { cb f7 [2] bf ef [2] f8 ed [2] bf fc [2] f1 f0 [2] fd fa [2] ea f1 [2] f1 bf [2] cc }

  condition:
    any of them
}