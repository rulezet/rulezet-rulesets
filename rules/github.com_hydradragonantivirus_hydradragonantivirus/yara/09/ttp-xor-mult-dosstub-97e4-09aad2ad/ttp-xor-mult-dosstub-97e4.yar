rule TTP_XOR_MULT_DOSStub_97e4 {
  strings:
    $key_97e4 = { c3 8c [2] b7 94 [2] f0 96 [2] b7 87 [2] f9 8b [2] f5 81 [2] e2 8a [2] f9 c4 [2] c4 }

  condition:
    any of them
}