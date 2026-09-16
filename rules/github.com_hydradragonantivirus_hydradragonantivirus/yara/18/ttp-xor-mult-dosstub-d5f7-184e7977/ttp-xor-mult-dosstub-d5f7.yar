rule TTP_XOR_MULT_DOSStub_d5f7 {
  strings:
    $key_d5f7 = { 81 9f [2] f5 87 [2] b2 85 [2] f5 94 [2] bb 98 [2] b7 92 [2] a0 99 [2] bb d7 [2] 86 }

  condition:
    any of them
}