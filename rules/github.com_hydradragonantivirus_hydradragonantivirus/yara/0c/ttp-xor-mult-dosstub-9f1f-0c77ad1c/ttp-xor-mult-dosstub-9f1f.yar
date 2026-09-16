rule TTP_XOR_MULT_DOSStub_9f1f {
  strings:
    $key_9f1f = { cb 77 [2] bf 6f [2] f8 6d [2] bf 7c [2] f1 70 [2] fd 7a [2] ea 71 [2] f1 3f [2] cc }

  condition:
    any of them
}