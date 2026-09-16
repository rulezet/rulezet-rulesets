rule TTP_XOR_MULT_DOSStub_9f35 {
  strings:
    $key_9f35 = { cb 5d [2] bf 45 [2] f8 47 [2] bf 56 [2] f1 5a [2] fd 50 [2] ea 5b [2] f1 15 [2] cc }

  condition:
    any of them
}