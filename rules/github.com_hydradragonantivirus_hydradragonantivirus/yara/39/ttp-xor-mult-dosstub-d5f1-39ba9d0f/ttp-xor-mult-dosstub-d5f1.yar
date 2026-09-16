rule TTP_XOR_MULT_DOSStub_d5f1 {
  strings:
    $key_d5f1 = { 81 99 [2] f5 81 [2] b2 83 [2] f5 92 [2] bb 9e [2] b7 94 [2] a0 9f [2] bb d1 [2] 86 }

  condition:
    any of them
}