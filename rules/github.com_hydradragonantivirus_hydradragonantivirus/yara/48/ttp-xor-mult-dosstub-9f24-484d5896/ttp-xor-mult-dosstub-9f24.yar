rule TTP_XOR_MULT_DOSStub_9f24 {
  strings:
    $key_9f24 = { cb 4c [2] bf 54 [2] f8 56 [2] bf 47 [2] f1 4b [2] fd 41 [2] ea 4a [2] f1 04 [2] cc }

  condition:
    any of them
}