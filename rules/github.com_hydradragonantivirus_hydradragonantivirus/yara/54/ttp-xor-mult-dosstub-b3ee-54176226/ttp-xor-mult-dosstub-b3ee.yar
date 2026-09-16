rule TTP_XOR_MULT_DOSStub_b3ee {
  strings:
    $key_b3ee = { e7 86 [2] 93 9e [2] d4 9c [2] 93 8d [2] dd 81 [2] d1 8b [2] c6 80 [2] dd ce [2] e0 }

  condition:
    any of them
}