rule TTP_XOR_MULT_DOSStub_9f5e {
  strings:
    $key_9f5e = { cb 36 [2] bf 2e [2] f8 2c [2] bf 3d [2] f1 31 [2] fd 3b [2] ea 30 [2] f1 7e [2] cc }

  condition:
    any of them
}