rule TTP_XOR_MULT_DOSStub_9f05 {
  strings:
    $key_9f05 = { cb 6d [2] bf 75 [2] f8 77 [2] bf 66 [2] f1 6a [2] fd 60 [2] ea 6b [2] f1 25 [2] cc }

  condition:
    any of them
}