rule TTP_XOR_MULT_DOSStub_9f49 {
  strings:
    $key_9f49 = { cb 21 [2] bf 39 [2] f8 3b [2] bf 2a [2] f1 26 [2] fd 2c [2] ea 27 [2] f1 69 [2] cc }

  condition:
    any of them
}