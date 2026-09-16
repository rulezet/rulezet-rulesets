rule TTP_XOR_MULT_DOSStub_9f5a {
  strings:
    $key_9f5a = { cb 32 [2] bf 2a [2] f8 28 [2] bf 39 [2] f1 35 [2] fd 3f [2] ea 34 [2] f1 7a [2] cc }

  condition:
    any of them
}