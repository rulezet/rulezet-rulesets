rule TTP_XOR_MULT_DOSStub_9f56 {
  strings:
    $key_9f56 = { cb 3e [2] bf 26 [2] f8 24 [2] bf 35 [2] f1 39 [2] fd 33 [2] ea 38 [2] f1 76 [2] cc }

  condition:
    any of them
}