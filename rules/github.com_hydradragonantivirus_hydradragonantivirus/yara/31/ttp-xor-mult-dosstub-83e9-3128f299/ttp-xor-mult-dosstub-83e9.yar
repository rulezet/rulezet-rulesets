rule TTP_XOR_MULT_DOSStub_83e9 {
  strings:
    $key_83e9 = { d7 81 [2] a3 99 [2] e4 9b [2] a3 8a [2] ed 86 [2] e1 8c [2] f6 87 [2] ed c9 [2] d0 }

  condition:
    any of them
}