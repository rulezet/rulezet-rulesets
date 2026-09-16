rule TTP_XOR_MULT_DOSStub_9f16 {
  strings:
    $key_9f16 = { cb 7e [2] bf 66 [2] f8 64 [2] bf 75 [2] f1 79 [2] fd 73 [2] ea 78 [2] f1 36 [2] cc }

  condition:
    any of them
}