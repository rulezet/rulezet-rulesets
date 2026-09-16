rule TTP_XOR_MULT_DOSStub_9f57 {
  strings:
    $key_9f57 = { cb 3f [2] bf 27 [2] f8 25 [2] bf 34 [2] f1 38 [2] fd 32 [2] ea 39 [2] f1 77 [2] cc }

  condition:
    any of them
}