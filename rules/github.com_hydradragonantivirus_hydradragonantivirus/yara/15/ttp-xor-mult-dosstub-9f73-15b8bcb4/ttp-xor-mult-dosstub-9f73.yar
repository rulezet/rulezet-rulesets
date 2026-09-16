rule TTP_XOR_MULT_DOSStub_9f73 {
  strings:
    $key_9f73 = { cb 1b [2] bf 03 [2] f8 01 [2] bf 10 [2] f1 1c [2] fd 16 [2] ea 1d [2] f1 53 [2] cc }

  condition:
    any of them
}