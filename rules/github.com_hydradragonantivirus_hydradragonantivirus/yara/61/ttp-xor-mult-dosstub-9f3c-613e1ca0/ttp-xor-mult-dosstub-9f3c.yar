rule TTP_XOR_MULT_DOSStub_9f3c {
  strings:
    $key_9f3c = { cb 54 [2] bf 4c [2] f8 4e [2] bf 5f [2] f1 53 [2] fd 59 [2] ea 52 [2] f1 1c [2] cc }

  condition:
    any of them
}