rule TTP_XOR_MULT_DOSStub_9f26 {
  strings:
    $key_9f26 = { cb 4e [2] bf 56 [2] f8 54 [2] bf 45 [2] f1 49 [2] fd 43 [2] ea 48 [2] f1 06 [2] cc }

  condition:
    any of them
}