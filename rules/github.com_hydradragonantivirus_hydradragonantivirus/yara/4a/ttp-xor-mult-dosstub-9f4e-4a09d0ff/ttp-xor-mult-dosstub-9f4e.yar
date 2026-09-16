rule TTP_XOR_MULT_DOSStub_9f4e {
  strings:
    $key_9f4e = { cb 26 [2] bf 3e [2] f8 3c [2] bf 2d [2] f1 21 [2] fd 2b [2] ea 20 [2] f1 6e [2] cc }

  condition:
    any of them
}