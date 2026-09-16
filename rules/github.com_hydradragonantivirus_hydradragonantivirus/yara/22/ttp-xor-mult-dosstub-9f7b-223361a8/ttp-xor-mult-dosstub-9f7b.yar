rule TTP_XOR_MULT_DOSStub_9f7b {
  strings:
    $key_9f7b = { cb 13 [2] bf 0b [2] f8 09 [2] bf 18 [2] f1 14 [2] fd 1e [2] ea 15 [2] f1 5b [2] cc }

  condition:
    any of them
}