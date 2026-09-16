rule TTP_XOR_MULT_DOSStub_e3ee {
  strings:
    $key_e3ee = { b7 86 [2] c3 9e [2] 84 9c [2] c3 8d [2] 8d 81 [2] 81 8b [2] 96 80 [2] 8d ce [2] b0 }

  condition:
    any of them
}