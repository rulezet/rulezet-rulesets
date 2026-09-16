rule TTP_XOR_MULT_DOSStub_9f13 {
  strings:
    $key_9f13 = { cb 7b [2] bf 63 [2] f8 61 [2] bf 70 [2] f1 7c [2] fd 76 [2] ea 7d [2] f1 33 [2] cc }

  condition:
    any of them
}