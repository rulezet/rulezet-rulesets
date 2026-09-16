rule TTP_XOR_MULT_DOSStub_83ee {
  strings:
    $key_83ee = { d7 86 [2] a3 9e [2] e4 9c [2] a3 8d [2] ed 81 [2] e1 8b [2] f6 80 [2] ed ce [2] d0 }

  condition:
    any of them
}