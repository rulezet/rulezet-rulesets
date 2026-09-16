rule TTP_XOR_MULT_DOSStub_9f21 {
  strings:
    $key_9f21 = { cb 49 [2] bf 51 [2] f8 53 [2] bf 42 [2] f1 4e [2] fd 44 [2] ea 4f [2] f1 01 [2] cc }

  condition:
    any of them
}