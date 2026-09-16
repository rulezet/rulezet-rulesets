rule TTP_XOR_MULT_DOSStub_9f77 {
  strings:
    $key_9f77 = { cb 1f [2] bf 07 [2] f8 05 [2] bf 14 [2] f1 18 [2] fd 12 [2] ea 19 [2] f1 57 [2] cc }

  condition:
    any of them
}