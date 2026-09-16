rule TTP_XOR_MULT_DOSStub_97e2 {
  strings:
    $key_97e2 = { c3 8a [2] b7 92 [2] f0 90 [2] b7 81 [2] f9 8d [2] f5 87 [2] e2 8c [2] f9 c2 [2] c4 }

  condition:
    any of them
}