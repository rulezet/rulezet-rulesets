rule TTP_XOR_MULT_DOSStub_97ee {
  strings:
    $key_97ee = { c3 86 [2] b7 9e [2] f0 9c [2] b7 8d [2] f9 81 [2] f5 8b [2] e2 80 [2] f9 ce [2] c4 }

  condition:
    any of them
}