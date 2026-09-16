rule TTP_XOR_MULT_DOSStub_d563 {
  strings:
    $key_d563 = { 81 0b [2] f5 13 [2] b2 11 [2] f5 00 [2] bb 0c [2] b7 06 [2] a0 0d [2] bb 43 [2] 86 }

  condition:
    any of them
}