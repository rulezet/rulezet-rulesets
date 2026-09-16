rule TTP_XOR_MULT_DOSStub_94e4 {
  strings:
    $key_94e4 = { c0 8c [2] b4 94 [2] f3 96 [2] b4 87 [2] fa 8b [2] f6 81 [2] e1 8a [2] fa c4 [2] c7 }

  condition:
    any of them
}