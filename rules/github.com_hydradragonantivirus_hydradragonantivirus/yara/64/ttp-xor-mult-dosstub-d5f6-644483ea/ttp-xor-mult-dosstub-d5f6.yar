rule TTP_XOR_MULT_DOSStub_d5f6 {
  strings:
    $key_d5f6 = { 81 9e [2] f5 86 [2] b2 84 [2] f5 95 [2] bb 99 [2] b7 93 [2] a0 98 [2] bb d6 [2] 86 }

  condition:
    any of them
}