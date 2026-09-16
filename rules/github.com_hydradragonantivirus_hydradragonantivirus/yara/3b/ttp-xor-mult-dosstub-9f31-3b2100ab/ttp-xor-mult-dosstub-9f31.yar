rule TTP_XOR_MULT_DOSStub_9f31 {
  strings:
    $key_9f31 = { cb 59 [2] bf 41 [2] f8 43 [2] bf 52 [2] f1 5e [2] fd 54 [2] ea 5f [2] f1 11 [2] cc }

  condition:
    any of them
}