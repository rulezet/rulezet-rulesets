rule TTP_XOR_MULT_DOSStub_d538 {
  strings:
    $key_d538 = { 81 50 [2] f5 48 [2] b2 4a [2] f5 5b [2] bb 57 [2] b7 5d [2] a0 56 [2] bb 18 [2] 86 }

  condition:
    any of them
}