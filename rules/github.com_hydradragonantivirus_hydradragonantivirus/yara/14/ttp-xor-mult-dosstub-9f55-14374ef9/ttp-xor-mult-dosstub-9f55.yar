rule TTP_XOR_MULT_DOSStub_9f55 {
  strings:
    $key_9f55 = { cb 3d [2] bf 25 [2] f8 27 [2] bf 36 [2] f1 3a [2] fd 30 [2] ea 3b [2] f1 75 [2] cc }

  condition:
    any of them
}