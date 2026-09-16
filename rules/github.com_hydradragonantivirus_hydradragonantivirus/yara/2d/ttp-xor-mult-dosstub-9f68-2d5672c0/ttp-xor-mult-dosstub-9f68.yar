rule TTP_XOR_MULT_DOSStub_9f68 {
  strings:
    $key_9f68 = { cb 00 [2] bf 18 [2] f8 1a [2] bf 0b [2] f1 07 [2] fd 0d [2] ea 06 [2] f1 48 [2] cc }

  condition:
    any of them
}