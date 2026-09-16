rule TTP_XOR_MULT_DOSStub_9f19 {
  strings:
    $key_9f19 = { cb 71 [2] bf 69 [2] f8 6b [2] bf 7a [2] f1 76 [2] fd 7c [2] ea 77 [2] f1 39 [2] cc }

  condition:
    any of them
}