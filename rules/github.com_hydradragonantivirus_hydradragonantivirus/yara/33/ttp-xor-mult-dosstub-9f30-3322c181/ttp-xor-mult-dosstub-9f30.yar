rule TTP_XOR_MULT_DOSStub_9f30 {
  strings:
    $key_9f30 = { cb 58 [2] bf 40 [2] f8 42 [2] bf 53 [2] f1 5f [2] fd 55 [2] ea 5e [2] f1 10 [2] cc }

  condition:
    any of them
}