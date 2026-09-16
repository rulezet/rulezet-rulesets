rule TTP_XOR_MULT_DOSStub_d568 {
  strings:
    $key_d568 = { 81 00 [2] f5 18 [2] b2 1a [2] f5 0b [2] bb 07 [2] b7 0d [2] a0 06 [2] bb 48 [2] 86 }

  condition:
    any of them
}