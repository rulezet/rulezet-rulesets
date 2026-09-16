rule TTP_XOR_MULT_DOSStub_9f08 {
  strings:
    $key_9f08 = { cb 60 [2] bf 78 [2] f8 7a [2] bf 6b [2] f1 67 [2] fd 6d [2] ea 66 [2] f1 28 [2] cc }

  condition:
    any of them
}