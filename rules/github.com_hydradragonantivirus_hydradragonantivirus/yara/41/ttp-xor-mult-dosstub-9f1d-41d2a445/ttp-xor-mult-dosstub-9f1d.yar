rule TTP_XOR_MULT_DOSStub_9f1d {
  strings:
    $key_9f1d = { cb 75 [2] bf 6d [2] f8 6f [2] bf 7e [2] f1 72 [2] fd 78 [2] ea 73 [2] f1 3d [2] cc }

  condition:
    any of them
}