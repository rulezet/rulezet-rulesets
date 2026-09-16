rule TTP_XOR_MULT_DOSStub_d559 {
  strings:
    $key_d559 = { 81 31 [2] f5 29 [2] b2 2b [2] f5 3a [2] bb 36 [2] b7 3c [2] a0 37 [2] bb 79 [2] 86 }

  condition:
    any of them
}