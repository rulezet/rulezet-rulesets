rule TTP_XOR_MULT_DOSStub_9f75 {
  strings:
    $key_9f75 = { cb 1d [2] bf 05 [2] f8 07 [2] bf 16 [2] f1 1a [2] fd 10 [2] ea 1b [2] f1 55 [2] cc }

  condition:
    any of them
}