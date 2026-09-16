rule TTP_XOR_MULT_DOSStub_9ffc {
  strings:
    $key_9ffc = { cb 94 [2] bf 8c [2] f8 8e [2] bf 9f [2] f1 93 [2] fd 99 [2] ea 92 [2] f1 dc [2] cc }

  condition:
    any of them
}