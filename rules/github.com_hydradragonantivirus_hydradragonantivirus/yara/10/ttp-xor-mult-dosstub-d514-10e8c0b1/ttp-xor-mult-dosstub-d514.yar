rule TTP_XOR_MULT_DOSStub_d514 {
  strings:
    $key_d514 = { 81 7c [2] f5 64 [2] b2 66 [2] f5 77 [2] bb 7b [2] b7 71 [2] a0 7a [2] bb 34 [2] 86 }

  condition:
    any of them
}