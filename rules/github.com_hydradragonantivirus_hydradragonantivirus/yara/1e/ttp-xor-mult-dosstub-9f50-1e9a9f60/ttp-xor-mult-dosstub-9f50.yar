rule TTP_XOR_MULT_DOSStub_9f50 {
  strings:
    $key_9f50 = { cb 38 [2] bf 20 [2] f8 22 [2] bf 33 [2] f1 3f [2] fd 35 [2] ea 3e [2] f1 70 [2] cc }

  condition:
    any of them
}