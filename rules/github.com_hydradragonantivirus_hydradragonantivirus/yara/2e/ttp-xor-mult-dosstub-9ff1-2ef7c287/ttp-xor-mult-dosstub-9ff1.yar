rule TTP_XOR_MULT_DOSStub_9ff1 {
  strings:
    $key_9ff1 = { cb 99 [2] bf 81 [2] f8 83 [2] bf 92 [2] f1 9e [2] fd 94 [2] ea 9f [2] f1 d1 [2] cc }

  condition:
    any of them
}