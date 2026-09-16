rule TTP_XOR_MULT_DOSStub_9f60 {
  strings:
    $key_9f60 = { cb 08 [2] bf 10 [2] f8 12 [2] bf 03 [2] f1 0f [2] fd 05 [2] ea 0e [2] f1 40 [2] cc }

  condition:
    any of them
}