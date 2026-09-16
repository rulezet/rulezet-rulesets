rule TTP_XOR_MULT_DOSStub_9f61 {
  strings:
    $key_9f61 = { cb 09 [2] bf 11 [2] f8 13 [2] bf 02 [2] f1 0e [2] fd 04 [2] ea 0f [2] f1 41 [2] cc }

  condition:
    any of them
}