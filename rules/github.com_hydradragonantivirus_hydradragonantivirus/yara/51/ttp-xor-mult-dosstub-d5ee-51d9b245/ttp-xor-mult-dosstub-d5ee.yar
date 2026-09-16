rule TTP_XOR_MULT_DOSStub_d5ee {
  strings:
    $key_d5ee = { 81 86 [2] f5 9e [2] b2 9c [2] f5 8d [2] bb 81 [2] b7 8b [2] a0 80 [2] bb ce [2] 86 }

  condition:
    any of them
}