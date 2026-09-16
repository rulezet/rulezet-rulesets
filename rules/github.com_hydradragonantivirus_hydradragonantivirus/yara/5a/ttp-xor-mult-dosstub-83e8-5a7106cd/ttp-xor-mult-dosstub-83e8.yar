rule TTP_XOR_MULT_DOSStub_83e8 {
  strings:
    $key_83e8 = { d7 80 [2] a3 98 [2] e4 9a [2] a3 8b [2] ed 87 [2] e1 8d [2] f6 86 [2] ed c8 [2] d0 }

  condition:
    any of them
}