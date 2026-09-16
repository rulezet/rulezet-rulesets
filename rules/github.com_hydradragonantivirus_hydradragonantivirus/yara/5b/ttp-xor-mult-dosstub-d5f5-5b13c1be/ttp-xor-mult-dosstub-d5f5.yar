rule TTP_XOR_MULT_DOSStub_d5f5 {
  strings:
    $key_d5f5 = { 81 9d [2] f5 85 [2] b2 87 [2] f5 96 [2] bb 9a [2] b7 90 [2] a0 9b [2] bb d5 [2] 86 }

  condition:
    any of them
}