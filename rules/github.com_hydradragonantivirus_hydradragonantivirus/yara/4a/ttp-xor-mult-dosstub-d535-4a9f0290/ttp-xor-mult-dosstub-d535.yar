rule TTP_XOR_MULT_DOSStub_d535 {
  strings:
    $key_d535 = { 81 5d [2] f5 45 [2] b2 47 [2] f5 56 [2] bb 5a [2] b7 50 [2] a0 5b [2] bb 15 [2] 86 }

  condition:
    any of them
}