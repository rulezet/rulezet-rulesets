rule TTP_XOR_MULT_DOSStub_9f4b {
  strings:
    $key_9f4b = { cb 23 [2] bf 3b [2] f8 39 [2] bf 28 [2] f1 24 [2] fd 2e [2] ea 25 [2] f1 6b [2] cc }

  condition:
    any of them
}