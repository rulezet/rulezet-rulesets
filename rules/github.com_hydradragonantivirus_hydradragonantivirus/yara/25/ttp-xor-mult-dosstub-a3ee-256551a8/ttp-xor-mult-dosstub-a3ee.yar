rule TTP_XOR_MULT_DOSStub_a3ee {
  strings:
    $key_a3ee = { f7 86 [2] 83 9e [2] c4 9c [2] 83 8d [2] cd 81 [2] c1 8b [2] d6 80 [2] cd ce [2] f0 }

  condition:
    any of them
}