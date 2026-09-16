rule TTP_XOR_MULT_DOSStub_9ffe {
  strings:
    $key_9ffe = { cb 96 [2] bf 8e [2] f8 8c [2] bf 9d [2] f1 91 [2] fd 9b [2] ea 90 [2] f1 de [2] cc }

  condition:
    any of them
}