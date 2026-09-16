rule TTP_XOR_MULT_DOSStub_9f45 {
  strings:
    $key_9f45 = { cb 2d [2] bf 35 [2] f8 37 [2] bf 26 [2] f1 2a [2] fd 20 [2] ea 2b [2] f1 65 [2] cc }

  condition:
    any of them
}