rule TTP_XOR_MULT_DOSStub_9f3b {
  strings:
    $key_9f3b = { cb 53 [2] bf 4b [2] f8 49 [2] bf 58 [2] f1 54 [2] fd 5e [2] ea 55 [2] f1 1b [2] cc }

  condition:
    any of them
}