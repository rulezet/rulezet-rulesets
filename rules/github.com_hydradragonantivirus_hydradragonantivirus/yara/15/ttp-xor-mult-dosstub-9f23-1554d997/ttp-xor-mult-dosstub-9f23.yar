rule TTP_XOR_MULT_DOSStub_9f23 {
  strings:
    $key_9f23 = { cb 4b [2] bf 53 [2] f8 51 [2] bf 40 [2] f1 4c [2] fd 46 [2] ea 4d [2] f1 03 [2] cc }

  condition:
    any of them
}