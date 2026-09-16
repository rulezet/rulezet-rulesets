rule TTP_XOR_MULT_DOSStub_9f63 {
  strings:
    $key_9f63 = { cb 0b [2] bf 13 [2] f8 11 [2] bf 00 [2] f1 0c [2] fd 06 [2] ea 0d [2] f1 43 [2] cc }

  condition:
    any of them
}