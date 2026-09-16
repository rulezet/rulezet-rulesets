rule TTP_XOR_MULT_DOSStub_9f03 {
  strings:
    $key_9f03 = { cb 6b [2] bf 73 [2] f8 71 [2] bf 60 [2] f1 6c [2] fd 66 [2] ea 6d [2] f1 23 [2] cc }

  condition:
    any of them
}