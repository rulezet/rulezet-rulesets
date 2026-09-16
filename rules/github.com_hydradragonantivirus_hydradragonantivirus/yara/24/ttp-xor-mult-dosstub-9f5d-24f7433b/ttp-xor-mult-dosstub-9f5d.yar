rule TTP_XOR_MULT_DOSStub_9f5d {
  strings:
    $key_9f5d = { cb 35 [2] bf 2d [2] f8 2f [2] bf 3e [2] f1 32 [2] fd 38 [2] ea 33 [2] f1 7d [2] cc }

  condition:
    any of them
}