rule TTP_XOR_MULT_DOSStub_a1ee {
  strings:
    $key_a1ee = { f5 86 [2] 81 9e [2] c6 9c [2] 81 8d [2] cf 81 [2] c3 8b [2] d4 80 [2] cf ce [2] f2 }

  condition:
    any of them
}