rule TTP_XOR_MULT_DOSStub_a7ee {
  strings:
    $key_a7ee = { f3 86 [2] 87 9e [2] c0 9c [2] 87 8d [2] c9 81 [2] c5 8b [2] d2 80 [2] c9 ce [2] f4 }

  condition:
    any of them
}