rule TTP_XOR_MULT_DOSStub_a6ee {
  strings:
    $key_a6ee = { f2 86 [2] 86 9e [2] c1 9c [2] 86 8d [2] c8 81 [2] c4 8b [2] d3 80 [2] c8 ce [2] f5 }

  condition:
    any of them
}