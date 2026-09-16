rule TTP_XOR_MULT_DOSStub_83e2 {
  strings:
    $key_83e2 = { d7 8a [2] a3 92 [2] e4 90 [2] a3 81 [2] ed 8d [2] e1 87 [2] f6 8c [2] ed c2 [2] d0 }

  condition:
    any of them
}