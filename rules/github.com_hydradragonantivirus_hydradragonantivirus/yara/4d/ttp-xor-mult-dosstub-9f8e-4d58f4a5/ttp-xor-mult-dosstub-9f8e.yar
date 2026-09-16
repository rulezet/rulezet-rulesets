rule TTP_XOR_MULT_DOSStub_9f8e {
  strings:
    $key_9f8e = { cb e6 [2] bf fe [2] f8 fc [2] bf ed [2] f1 e1 [2] fd eb [2] ea e0 [2] f1 ae [2] cc }

  condition:
    any of them
}