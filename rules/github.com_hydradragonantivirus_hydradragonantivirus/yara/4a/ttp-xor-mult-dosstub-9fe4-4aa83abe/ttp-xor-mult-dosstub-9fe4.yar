rule TTP_XOR_MULT_DOSStub_9fe4 {
  strings:
    $key_9fe4 = { cb 8c [2] bf 94 [2] f8 96 [2] bf 87 [2] f1 8b [2] fd 81 [2] ea 8a [2] f1 c4 [2] cc }

  condition:
    any of them
}