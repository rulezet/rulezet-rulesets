rule TTP_XOR_MULT_DOSStub_9f46 {
  strings:
    $key_9f46 = { cb 2e [2] bf 36 [2] f8 34 [2] bf 25 [2] f1 29 [2] fd 23 [2] ea 28 [2] f1 66 [2] cc }

  condition:
    any of them
}