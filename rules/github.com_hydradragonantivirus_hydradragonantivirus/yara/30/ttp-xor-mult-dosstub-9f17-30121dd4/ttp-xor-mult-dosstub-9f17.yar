rule TTP_XOR_MULT_DOSStub_9f17 {
  strings:
    $key_9f17 = { cb 7f [2] bf 67 [2] f8 65 [2] bf 74 [2] f1 78 [2] fd 72 [2] ea 79 [2] f1 37 [2] cc }

  condition:
    any of them
}