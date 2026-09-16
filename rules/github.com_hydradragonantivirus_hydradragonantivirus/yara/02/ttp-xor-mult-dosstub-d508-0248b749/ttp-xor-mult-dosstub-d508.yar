rule TTP_XOR_MULT_DOSStub_d508 {
  strings:
    $key_d508 = { 81 60 [2] f5 78 [2] b2 7a [2] f5 6b [2] bb 67 [2] b7 6d [2] a0 66 [2] bb 28 [2] 86 }

  condition:
    any of them
}