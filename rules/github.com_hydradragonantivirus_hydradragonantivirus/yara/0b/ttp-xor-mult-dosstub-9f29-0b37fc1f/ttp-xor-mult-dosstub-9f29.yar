rule TTP_XOR_MULT_DOSStub_9f29 {
  strings:
    $key_9f29 = { cb 41 [2] bf 59 [2] f8 5b [2] bf 4a [2] f1 46 [2] fd 4c [2] ea 47 [2] f1 09 [2] cc }

  condition:
    any of them
}