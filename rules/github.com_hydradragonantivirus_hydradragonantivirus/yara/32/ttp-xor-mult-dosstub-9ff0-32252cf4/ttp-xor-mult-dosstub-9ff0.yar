rule TTP_XOR_MULT_DOSStub_9ff0 {
  strings:
    $key_9ff0 = { cb 98 [2] bf 80 [2] f8 82 [2] bf 93 [2] f1 9f [2] fd 95 [2] ea 9e [2] f1 d0 [2] cc }

  condition:
    any of them
}