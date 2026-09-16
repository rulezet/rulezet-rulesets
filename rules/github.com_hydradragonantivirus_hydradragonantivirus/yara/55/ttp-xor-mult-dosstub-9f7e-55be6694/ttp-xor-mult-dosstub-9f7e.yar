rule TTP_XOR_MULT_DOSStub_9f7e {
  strings:
    $key_9f7e = { cb 16 [2] bf 0e [2] f8 0c [2] bf 1d [2] f1 11 [2] fd 1b [2] ea 10 [2] f1 5e [2] cc }

  condition:
    any of them
}