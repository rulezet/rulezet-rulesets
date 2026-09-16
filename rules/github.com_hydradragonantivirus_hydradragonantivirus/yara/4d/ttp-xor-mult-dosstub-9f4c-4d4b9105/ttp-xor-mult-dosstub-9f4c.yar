rule TTP_XOR_MULT_DOSStub_9f4c {
  strings:
    $key_9f4c = { cb 24 [2] bf 3c [2] f8 3e [2] bf 2f [2] f1 23 [2] fd 29 [2] ea 22 [2] f1 6c [2] cc }

  condition:
    any of them
}