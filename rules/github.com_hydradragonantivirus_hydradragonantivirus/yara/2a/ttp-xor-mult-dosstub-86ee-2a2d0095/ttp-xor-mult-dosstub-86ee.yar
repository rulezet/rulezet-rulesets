rule TTP_XOR_MULT_DOSStub_86ee {
  strings:
    $key_86ee = { d2 86 [2] a6 9e [2] e1 9c [2] a6 8d [2] e8 81 [2] e4 8b [2] f3 80 [2] e8 ce [2] d5 }

  condition:
    any of them
}