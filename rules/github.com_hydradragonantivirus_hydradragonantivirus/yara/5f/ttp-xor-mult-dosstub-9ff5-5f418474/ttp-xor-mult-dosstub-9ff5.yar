rule TTP_XOR_MULT_DOSStub_9ff5 {
  strings:
    $key_9ff5 = { cb 9d [2] bf 85 [2] f8 87 [2] bf 96 [2] f1 9a [2] fd 90 [2] ea 9b [2] f1 d5 [2] cc }

  condition:
    any of them
}