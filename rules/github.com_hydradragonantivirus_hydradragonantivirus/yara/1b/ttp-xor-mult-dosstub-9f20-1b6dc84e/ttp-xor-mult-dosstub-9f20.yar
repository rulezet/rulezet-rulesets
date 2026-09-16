rule TTP_XOR_MULT_DOSStub_9f20 {
  strings:
    $key_9f20 = { cb 48 [2] bf 50 [2] f8 52 [2] bf 43 [2] f1 4f [2] fd 45 [2] ea 4e [2] f1 00 [2] cc }

  condition:
    any of them
}