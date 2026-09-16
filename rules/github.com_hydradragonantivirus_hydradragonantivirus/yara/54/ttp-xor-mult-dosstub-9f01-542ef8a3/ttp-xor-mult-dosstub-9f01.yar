rule TTP_XOR_MULT_DOSStub_9f01 {
  strings:
    $key_9f01 = { cb 69 [2] bf 71 [2] f8 73 [2] bf 62 [2] f1 6e [2] fd 64 [2] ea 6f [2] f1 21 [2] cc }

  condition:
    any of them
}