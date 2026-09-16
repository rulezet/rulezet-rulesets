rule TTP_XOR_MULT_DOSStub_d503 {
  strings:
    $key_d503 = { 81 6b [2] f5 73 [2] b2 71 [2] f5 60 [2] bb 6c [2] b7 66 [2] a0 6d [2] bb 23 [2] 86 }

  condition:
    any of them
}