rule TTP_XOR_MULT_DOSStub_94e2 {
  strings:
    $key_94e2 = { c0 8a [2] b4 92 [2] f3 90 [2] b4 81 [2] fa 8d [2] f6 87 [2] e1 8c [2] fa c2 [2] c7 }

  condition:
    any of them
}