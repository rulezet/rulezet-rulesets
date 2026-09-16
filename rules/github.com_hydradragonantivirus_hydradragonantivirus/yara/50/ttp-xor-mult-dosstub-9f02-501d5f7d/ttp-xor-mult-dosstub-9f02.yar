rule TTP_XOR_MULT_DOSStub_9f02 {
  strings:
    $key_9f02 = { cb 6a [2] bf 72 [2] f8 70 [2] bf 61 [2] f1 6d [2] fd 67 [2] ea 6c [2] f1 22 [2] cc }

  condition:
    any of them
}