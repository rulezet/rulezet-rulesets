rule TTP_XOR_MULT_DOSStub_d564 {
  strings:
    $key_d564 = { 81 0c [2] f5 14 [2] b2 16 [2] f5 07 [2] bb 0b [2] b7 01 [2] a0 0a [2] bb 44 [2] 86 }

  condition:
    any of them
}