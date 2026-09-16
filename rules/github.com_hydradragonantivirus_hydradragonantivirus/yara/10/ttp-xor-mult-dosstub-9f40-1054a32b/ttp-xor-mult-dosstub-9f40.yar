rule TTP_XOR_MULT_DOSStub_9f40 {
  strings:
    $key_9f40 = { cb 28 [2] bf 30 [2] f8 32 [2] bf 23 [2] f1 2f [2] fd 25 [2] ea 2e [2] f1 60 [2] cc }

  condition:
    any of them
}