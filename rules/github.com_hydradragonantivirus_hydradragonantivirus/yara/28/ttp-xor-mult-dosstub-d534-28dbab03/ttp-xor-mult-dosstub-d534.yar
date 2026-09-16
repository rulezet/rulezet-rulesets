rule TTP_XOR_MULT_DOSStub_d534 {
  strings:
    $key_d534 = { 81 5c [2] f5 44 [2] b2 46 [2] f5 57 [2] bb 5b [2] b7 51 [2] a0 5a [2] bb 14 [2] 86 }

  condition:
    any of them
}